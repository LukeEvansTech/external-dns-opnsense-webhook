package opnsense

import (
	"context"
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
	return &Provider{cfg: cfg, client: c, filter: endpoint.NewDomainFilter(cfg.Domains)}, nil
}

// GetDomainFilter returns OPNSENSE_DOMAINS, negotiated back to external-dns
// on GET /.
func (p *Provider) GetDomainFilter() endpoint.DomainFilterInterface { return p.filter }

// Records returns the current host overrides as endpoints. A pending
// reconfigure is applied first so the table returned is the table served.
func (p *Provider) Records(ctx context.Context) (eps []*endpoint.Endpoint, err error) {
	defer func() { metrics.Get().RecordOperation(err) }()
	if p.pending.Load() {
		if rerr := p.reconfigure(); rerr != nil {
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
	start := time.Now()
	defer func() {
		metrics.Get().ApplyDuration.WithLabelValues(metrics.ProviderName).Observe(time.Since(start).Seconds())
		metrics.Get().RecordOperation(err)
	}()
	p.applyMu.Lock()
	defer p.applyMu.Unlock()

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
		reason := ""
		switch {
		case e.RecordType != recordTypeA && e.RecordType != recordTypeAAAA && e.RecordType != recordTypeTXT:
			reason = "type"
		case isWildcard(name):
			reason = "wildcard"
		case !inDomains(name, p.cfg.Domains):
			reason = "domain"
		}
		if reason != "" {
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

// reconfigure runs under its own bounded context, detached from any request,
// because a cancelled request must not leave saved and served state apart.
func (p *Provider) reconfigure() error {
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
