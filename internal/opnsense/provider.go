package opnsense

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LukeEvansTech/external-dns-opnsense-webhook/internal/metrics"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

// Provider is the external-dns provider over OPNsense Unbound host overrides.
type Provider struct {
	provider.BaseProvider

	cfg    *Config
	client *Client
	filter *endpoint.DomainFilter

	// applyMu serialises ApplyChanges. external-dns is sequential, so
	// contention only follows a client timeout; the late request waits.
	applyMu sync.Mutex
	// reconfigureMu serialises the reload itself, which applies and reads can
	// both reach. Two concurrent reloads of the same saved table are wasted
	// work on a firewall that restarts Unbound to honour them.
	reconfigureMu sync.Mutex
	// pending is set before the first write of an apply and cleared only by
	// a successful reconfigure, so a failed reload is repaired even when the
	// next plan is empty.
	pending atomic.Bool
}

// NewProvider validates cfg and builds the provider. It performs no I/O;
// Startup probes the firewall after the listeners are up.
func NewProvider(cfg *Config) (*Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid opnsense configuration: %w", err)
	}
	c, err := NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating opnsense client: %w", err)
	}
	p := &Provider{cfg: cfg, client: c, filter: endpoint.NewDomainFilter(cfg.Domains)}
	// Publish the gauge at zero so the series exists before the first apply:
	// an alert on it must be able to tell "not pending" from "never reported".
	p.setPending(false)
	return p, nil
}

// GetDomainFilter returns OPNSENSE_DOMAINS, negotiated back to external-dns
// on GET /.
func (p *Provider) GetDomainFilter() endpoint.DomainFilterInterface { return p.filter }

// Records returns the current host overrides as endpoints. A pending
// reconfigure is applied first so the table returned is the table served.
func (p *Provider) Records(ctx context.Context) (eps []*endpoint.Endpoint, err error) {
	defer func() { metrics.Get().RecordOperation(err) }()
	if p.pending.Load() {
		if rerr := p.reconfigure(true); rerr != nil {
			return nil, fmt.Errorf("applying pending reconfigure before read: %w", rerr)
		}
	}
	snap, err := p.client.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	metrics.Get().RowsTotal.WithLabelValues(metrics.ProviderName).Set(float64(snap.Total))
	eps = snap.Endpoints()
	byType := map[string]int{}
	for _, e := range eps {
		byType[e.RecordType]++
	}
	for _, rr := range []string{recordTypeA, recordTypeAAAA, recordTypeTXT, recordTypeMX} {
		metrics.Get().UpdateRecordsByType(rr, byType[rr])
	}
	return eps, nil
}

// ApplyChanges converges the table towards the plan (apply.go) under a
// detached, bounded context and the single-writer lock.
func (p *Provider) ApplyChanges(ctx context.Context, changes *plan.Changes) (err error) {
	p.applyMu.Lock()
	defer p.applyMu.Unlock()

	// Timed from here rather than from entry: waiting for the single-writer
	// lock is queueing, not apply work, and folding it in would make the
	// histogram report a slow firewall whenever two requests overlapped.
	start := time.Now()
	defer func() {
		metrics.Get().ApplyDuration.WithLabelValues(metrics.ProviderName).Observe(time.Since(start).Seconds())
		metrics.Get().RecordOperation(err)
	}()

	// Detached from the request: a client that hangs up mid-apply must not
	// abandon the table half-converged, or leave saved and served apart.
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.cfg.ApplyTimeout)
	defer cancel()
	return p.apply(actx, changes)
}

// AdjustEndpoints canonicalises names and TTLs and drops what the model
// cannot hold, so external-dns never loops on an unwritable endpoint.
func (p *Provider) AdjustEndpoints(in []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
	m := metrics.Get()
	out := make([]*endpoint.Endpoint, 0, len(in))
	for _, e := range in {
		name := normaliseName(e.DNSName)
		if reason := p.dropReason(e, name); reason != "" {
			m.EndpointsDroppedTotal.WithLabelValues(metrics.ProviderName, reason).Inc()
			slog.Warn("dropping endpoint the provider cannot write", "name", e.DNSName, "type", e.RecordType, "reason", reason)
			continue
		}
		adj := e.DeepCopy()
		adj.DNSName = name
		adj.RecordTTL = endpoint.TTL(clampTTL(e.RecordTTL))
		out = append(out, adj)
	}
	return out, nil
}

// dropReason names why an endpoint cannot be written, or "" when it can. The
// set of reasons is closed (metrics.DropReasons) because it is a metric label,
// and each reason's counter child exists from startup; it mirrors what the write path
// rejects: an endpoint external-dns is allowed to keep desiring but the
// provider can never create is a plan that never converges, and external-dns
// would retry it every pass forever.
func (p *Provider) dropReason(e *endpoint.Endpoint, name string) string {
	switch {
	case e.RecordType != recordTypeA && e.RecordType != recordTypeAAAA && e.RecordType != recordTypeTXT:
		return metrics.DropReasonType
	case e.SetIdentifier != "":
		// Host overrides have no way to hold two record sets of the same name
		// and type apart, so a weighted or latency policy cannot be expressed.
		return metrics.DropReasonSetIdentifier
	case isWildcard(name):
		return metrics.DropReasonWildcard
	}
	if _, _, err := splitName(name, p.cfg.Domains); err != nil {
		switch {
		case errors.Is(err, ErrApexName):
			return metrics.DropReasonApex
		case errors.Is(err, ErrNameOutsideDomains):
			return metrics.DropReasonDomain
		default:
			return metrics.DropReasonName
		}
	}
	if e.RecordType == recordTypeTXT {
		for _, t := range e.Targets {
			if _, err := validateTXT(t); err != nil {
				metrics.Get().TXTInvalidTotal.WithLabelValues(metrics.ProviderName).Inc()
				return metrics.DropReasonTXT
			}
		}
	}
	return ""
}

// reconfigure runs under its own bounded context, detached from any request,
// because a cancelled request must not leave saved and served state apart.
//
// repair marks a call made only because an earlier reconfigure failed. Several
// reads can notice the same pending flag at once; whichever reaches the lock
// first does the work, and the rest find the flag already cleared and return
// without reloading the firewall again. An apply's own trailing reconfigure is
// never a repair: it has just written, so it must always reload.
func (p *Provider) reconfigure(repair bool) error {
	p.reconfigureMu.Lock()
	defer p.reconfigureMu.Unlock()
	if repair && !p.pending.Load() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.ReconfigureTimeout)
	defer cancel()
	err := p.client.Reconfigure(ctx)
	metrics.Get().RecordReconfigure(err)
	if err != nil {
		p.setPending(true)
		return err
	}
	p.setPending(false)
	return nil
}

func (p *Provider) setPending(v bool) {
	p.pending.Store(v)
	g := 0.0
	if v {
		g = 1
	}
	metrics.Get().PendingReconfigure.WithLabelValues(metrics.ProviderName).Set(g)
}

// Startup probes the firewall and repairs saved-but-unserved managed rows.
// It is called in the background after the listeners are bound: external-dns
// negotiates GET / with only a few retries, so the webhook must answer before
// the firewall does. Failures are logged and leave /readyz failing; they
// never exit the process.
func (p *Provider) Startup(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.ApplyTimeout)
	defer cancel()
	if err := p.client.ServiceStatus(ctx); err != nil {
		logStartupFailure("opnsense unreachable at startup; readiness will report the cause", err)
		return
	}
	if err := p.servedStateCheck(ctx); err != nil {
		logStartupFailure("served-state check failed", err)
	}
}

// logStartupFailure keeps a shutdown out of the error log. ctx is cancelled
// when the process is signalled, so a Startup still in flight then fails with
// context.Canceled — expected, not a fault to page anyone about.
func logStartupFailure(msg string, err error) {
	if errors.Is(err, context.Canceled) {
		slog.Info("startup check aborted: shutting down", "during", msg)
		return
	}
	slog.Error(msg, "error", err)
}

// servedStateCheck compares managed rows in the saved configuration with
// what Unbound serves and reconfigures once if any is missing. The owner
// marker is a heuristic for this check only.
func (p *Provider) servedStateCheck(ctx context.Context) error {
	snap, err := p.client.Snapshot(ctx)
	if err != nil {
		return err
	}
	served, err := p.client.ListLocalData(ctx)
	if err != nil {
		return err
	}
	have := map[rowKey]struct{}{}
	for _, d := range served {
		have[rowKey{name: normaliseName(d.Name), rr: d.RRType}] = struct{}{}
	}
	missing := 0
	// Only parent rows are checked. OPNsense renders a row and every alias
	// hanging off it from the same save, so a parent and its aliases are
	// served or missing together: checking the parent alone cannot miss an
	// unserved alias, and checking children too would only repeat the verdict.
	for _, r := range snap.rows { // rows is []*hostRow (pointer-stable since Task 8)
		if !r.enabled() || bool(r.IsAlias) || r.Description != p.cfg.OwnerMarker {
			continue
		}
		if _, ok := have[rowKey{name: joinName(r.Hostname, r.Domain), rr: r.RR}]; !ok {
			missing++
			slog.Warn("managed override saved but not served", "name", joinName(r.Hostname, r.Domain), "type", r.RR, "uuid", r.UUID)
		}
	}
	if missing == 0 {
		return nil
	}
	slog.Info("reconfiguring Unbound to publish unserved managed rows", "missing", missing)
	p.setPending(true)
	// Not a repair: the pending flag was set a line ago solely to make this
	// reload self-healing if it fails, so it must always reload.
	return p.reconfigure(false)
}

// Ready is the readiness probe: one cheap page read. It reports not-ready
// while the API is unreachable or the credentials are wrong.
func (p *Provider) Ready(ctx context.Context) error {
	_, err := p.client.SearchHostOverrides(ctx, 1, 1)
	return err
}

// ApplyBudget is the worst-case wall time of one ApplyChanges: the apply
// timeout plus the trailing reconfigure, which runs on its own context.
func (p *Provider) ApplyBudget() time.Duration {
	return p.cfg.ApplyTimeout + p.cfg.ReconfigureTimeout
}
