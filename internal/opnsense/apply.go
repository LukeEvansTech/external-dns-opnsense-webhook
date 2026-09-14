package opnsense

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/LukeEvansTech/external-dns-opnsense-webhook/internal/metrics"
	"golang.org/x/sync/errgroup"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

// desiredSet is the target set one (name, type) should end up with. TXT
// targets are stored bare (quotes stripped) so they compare with rows.
type desiredSet struct {
	key     rowKey
	targets map[string]struct{}
	ttl     int64
	// failed records that the add/set phase for this key could not write
	// every desired target. The remove phase then leaves the key's surplus
	// rows alone: dropping them would shrink a record set the plan meant to
	// grow or replace, and could leave the name resolving to nothing.
	failed bool
}

type convergeMode int

const (
	modeAddSet convergeMode = iota
	modeRemove
)

func isTXT(rr string) bool  { return rr == recordTypeTXT }
func isData(rr string) bool { return rr != recordTypeTXT }

// applyPhases keeps invariant I1: a registry TXT row is created before the
// data rows it describes and removed after them. Each phase drains before the
// next starts, so the ordering holds across a failure boundary too.
//
// Ordering alone is not enough, because a phase can fail. gatedOn names the
// protective phase that must have completed without a failure before this
// phase may run: creating data rows whose TXT row was not written would leave
// records nothing claims ownership of, and removing a TXT row whose data rows
// are still there would strand them the same way. A gated-out phase is skipped
// for this cycle and converges on the next one, once the protective phase has
// succeeded. The protective phases themselves always run.
var applyPhases = []struct {
	selects func(rr string) bool
	mode    convergeMode
	gatedOn int
	skip    string
}{
	{isTXT, modeAddSet, noGate, ""},
	{isData, modeAddSet, 0, "skipping data creates: TXT writes failed this cycle"},
	{isData, modeRemove, noGate, ""},
	{isTXT, modeRemove, 2, "skipping TXT removes: data deletes failed this cycle"},
}

// noGate marks a phase that runs unconditionally.
const noGate = -1

// applyRun is the mutable state of one ApplyChanges. mu guards all of it, the
// snapshot index included: several keys converge concurrently and every one of
// them can add or remove rows.
//
// The rows themselves are read and written outside mu. That is safe because a
// phase gives each rowKey to exactly one goroutine, and a row belongs to
// exactly one rowKey, so no two workers ever touch the same *hostRow; only the
// index they hang off is shared, and every path into it takes mu.
type applyRun struct {
	p    *Provider
	snap *Snapshot

	mu    sync.Mutex
	errs  []error
	wrote bool
	// phaseFailed counts converge failures within the phase now running; apply
	// resets it before each phase and reads it once the phase has drained.
	phaseFailed int
}

// fail records a converge error and marks the key, so the remove phase knows
// not to trust the add/set phase's outcome for it.
func (r *applyRun) fail(set *desiredSet, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, err)
	r.phaseFailed++
	set.failed = true
}

// startPhase clears the per-phase failure count; endPhase reports it once the
// phase has drained.
func (r *applyRun) startPhase() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.phaseFailed = 0
}

func (r *applyRun) endPhase() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.phaseFailed
}

func (r *applyRun) didFail(set *desiredSet) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return set.failed
}

// markWrite sets the pending flag before the first write of the apply
// (invariant I4); only a successful reconfigure clears it again.
func (r *applyRun) markWrite() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.wrote {
		r.wrote = true
		r.p.setPending(true)
	}
}

// rows copies the snapshot's rows for k. The copy matters: removeRow compacts
// the indexed slice in place, so iterating what rowsFor returned while
// deleting from it would skip rows.
func (r *applyRun) rows(k rowKey) []*hostRow {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*hostRow(nil), r.snap.rowsFor(k)...)
}

func (r *applyRun) addRow(row hostRow) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snap.add(row)
}

func (r *applyRun) removeRow(k rowKey, uuid string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snap.remove(k, uuid)
}

// retarget records a write the firewall accepted against the snapshot row, so
// a later phase sees the row as it now is rather than as it was read. byKey is
// the only index the apply path consults and its key (name, rr) is unchanged
// by a write, so nothing needs reindexing.
func (r *applyRun) retarget(row *hostRow, f hostFields) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row.Hostname, row.Domain, row.RR = f.Hostname, f.Domain, f.RR
	row.Server, row.TXTData = f.Server, f.TXTData
	row.TTL, row.AddPTR, row.Description = f.TTL, f.AddPTR, f.Description
}

// foldChanges turns the plan into one desired set per key. Create and
// UpdateNew define the set, Delete empties it; UpdateOld describes the state
// being replaced and is read from the snapshot instead. Endpoints that fail
// validation are reported and skipped; nothing else in the plan is affected.
func (p *Provider) foldChanges(changes *plan.Changes) (map[rowKey]*desiredSet, []error) {
	sets := map[rowKey]*desiredSet{}
	var errs []error
	define := func(e *endpoint.Endpoint, empty bool) {
		name := normaliseName(e.DNSName)
		if _, _, err := splitName(name, p.cfg.Domains); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", e.RecordType, name, err))
			return
		}
		k := rowKey{name: name, rr: e.RecordType}
		set := &desiredSet{key: k, targets: map[string]struct{}{}, ttl: clampTTL(e.RecordTTL)}
		if !empty {
			for _, t := range e.Targets {
				switch e.RecordType {
				case recordTypeA, recordTypeAAAA:
					set.targets[t] = struct{}{}
				case recordTypeTXT:
					bare, err := validateTXT(t)
					if err != nil {
						metrics.Get().TXTInvalidTotal.WithLabelValues(metrics.ProviderName).Inc()
						errs = append(errs, fmt.Errorf("TXT %s: %w", name, err))
						return
					}
					set.targets[bare] = struct{}{}
				default:
					errs = append(errs, fmt.Errorf("%s %s: %w", e.RecordType, name, ErrUnsupportedType))
					return
				}
			}
		}
		sets[k] = set
	}
	for _, e := range changes.Delete {
		define(e, true)
	}
	for _, e := range changes.Create {
		define(e, false)
	}
	for _, e := range changes.UpdateNew {
		define(e, false)
	}
	return sets, errs
}

// apply runs the four phases from the design: TXT add/set, data add/set, data
// remove, TXT remove. Each phase drains before the next so a data row never
// exists without its TXT row across a failure boundary.
func (p *Provider) apply(ctx context.Context, changes *plan.Changes) error {
	snap, err := p.client.Snapshot(ctx)
	if err != nil {
		return err
	}
	sets, errs := p.foldChanges(changes)
	run := &applyRun{p: p, snap: snap, errs: errs}

	keys := make([]rowKey, 0, len(sets))
	for k := range sets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].name < keys[j].name })

	failures := make([]int, len(applyPhases))
	for i, ph := range applyPhases {
		if ph.gatedOn != noGate && failures[ph.gatedOn] > 0 {
			slog.Warn(ph.skip, "failures", failures[ph.gatedOn])
			continue
		}
		run.startPhase()
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(p.cfg.ApplyWorkers)
		for _, k := range keys {
			if !ph.selects(k.rr) {
				continue
			}
			set := sets[k]
			g.Go(func() error {
				if cerr := p.converge(gctx, run, set, ph.mode); cerr != nil {
					run.fail(set, cerr)
				}
				return nil
			})
		}
		// Every goroutine returns nil: one key's failure must not cancel the
		// others, and the errors are collected rather than propagated.
		_ = g.Wait()
		failures[i] = run.endPhase()
	}

	// A write attempt, committed or not, means saved and served may differ; so
	// does a reconfigure an earlier apply could not complete. Either way the
	// firewall is reloaded here rather than left waiting for the next read.
	if run.wrote || p.pending.Load() {
		if rerr := p.reconfigure(); rerr != nil {
			run.errs = append(run.errs, fmt.Errorf("reconfigure: %w", rerr))
		}
	}
	return errors.Join(run.errs...)
}

// converge brings one key's rows towards its desired set in the given mode.
func (p *Provider) converge(ctx context.Context, run *applyRun, set *desiredSet, mode convergeMode) error {
	host, domain, err := splitName(set.key.name, p.cfg.Domains)
	if err != nil {
		return err
	}
	existing := run.rows(set.key)
	if mode == modeRemove {
		return p.removeSurplus(ctx, run, set, existing)
	}
	return p.addSet(ctx, run, set, host, domain, existing)
}

// addSet makes every desired target present: rows already carrying one are
// brought into line, rows the plan no longer wants are reused for the targets
// that have none, and only what is still missing is created.
func (p *Provider) addSet(ctx context.Context, run *applyRun, set *desiredSet, host, domain string, existing []*hostRow) error {
	byTarget := make(map[string]*hostRow, len(existing))
	for _, r := range existing {
		byTarget[r.bareTarget()] = r
	}
	targets := sortedTargets(set.targets)

	for _, t := range targets {
		r, ok := byTarget[t]
		if !ok {
			continue
		}
		f := p.fields(host, domain, set.key.rr, t, set.ttl)
		if r.ttlValue() == set.ttl && r.Description == f.Description && r.AddPTR == f.AddPTR {
			continue
		}
		if err := p.setRow(ctx, run, set.key, r, f, t); err != nil {
			return err
		}
	}

	// A target with no row takes over a row the plan no longer wants before a
	// new one is created. setHostOverride keeps the uuid and the alias
	// children hanging off it, the change is one call rather than an add and
	// a delete, and the name never drops to zero rows on the way (invariant
	// I2). A row with alias children could not be deleted at all (the delete
	// guard), so reuse is the only way such a name ever converges.
	//
	// Two consequences worth knowing. Reuse rewrites the row's description to
	// OPNSENSE_OWNER_MARKER, so a hand-made row sitting at a managed name is
	// adopted rather than left alone. And missing targets are paired with
	// surplus rows by sorted order, which is deterministic but otherwise
	// arbitrary: nothing makes a particular target land on a particular uuid,
	// so an alias child follows whichever target its row is reused for.
	missing := make([]string, 0, len(targets))
	for _, t := range targets {
		if _, ok := byTarget[t]; !ok {
			missing = append(missing, t)
		}
	}
	surplus := make([]*hostRow, 0, len(existing))
	for _, r := range existing {
		if _, keep := set.targets[r.bareTarget()]; !keep {
			surplus = append(surplus, r)
		}
	}
	reused := min(len(missing), len(surplus))
	for i := range reused {
		f := p.fields(host, domain, set.key.rr, missing[i], set.ttl)
		if err := p.setRow(ctx, run, set.key, surplus[i], f, missing[i]); err != nil {
			return err
		}
	}
	for _, t := range missing[reused:] {
		if err := p.createRow(ctx, run, set.key, p.fields(host, domain, set.key.rr, t, set.ttl), t); err != nil {
			return err
		}
	}
	return nil
}

// removeSurplus deletes the key's rows the desired set no longer names.
func (p *Provider) removeSurplus(ctx context.Context, run *applyRun, set *desiredSet, existing []*hostRow) error {
	if len(set.targets) > 0 && run.didFail(set) {
		slog.Warn("keeping surplus rows after a failed converge", "name", set.key.name, "type", set.key.rr)
		return nil
	}
	for _, r := range existing {
		if _, keep := set.targets[r.bareTarget()]; keep {
			continue
		}
		if hasEnabledChildren(r) {
			metrics.Get().DeleteBlockedTotal.WithLabelValues(metrics.ProviderName).Inc()
			return fmt.Errorf("delete %s %s (%s): %w", set.key.rr, set.key.name, r.UUID, ErrAliasChildren)
		}
		run.markWrite()
		deleted, err := p.client.DelHostOverride(ctx, r.UUID)
		if err != nil {
			return fmt.Errorf("delete %s %s (%s): %w", set.key.rr, set.key.name, r.UUID, err)
		}
		run.removeRow(set.key, r.UUID)
		if deleted {
			metrics.Get().RecordChange("delete", set.key.rr)
			slog.Info("deleted override", "name", set.key.name, "type", set.key.rr, "target", r.bareTarget(), "uuid", r.UUID)
			continue
		}
		slog.Info("override already gone", "name", set.key.name, "type", set.key.rr, "uuid", r.UUID)
	}
	return nil
}

// setRow rewrites one row in place, keeping its uuid and alias children.
func (p *Provider) setRow(ctx context.Context, run *applyRun, k rowKey, r *hostRow, f hostFields, target string) error {
	run.markWrite()
	if err := p.client.SetHostOverride(ctx, r.UUID, f); err != nil {
		return fmt.Errorf("set %s %s -> %s: %w", k.rr, k.name, target, err)
	}
	run.retarget(r, f)
	metrics.Get().RecordChange("update", k.rr)
	slog.Info("updated override", "name", k.name, "type", k.rr, "target", target, "uuid", r.UUID)
	return nil
}

// createRow creates one row and records it in the snapshot.
func (p *Provider) createRow(ctx context.Context, run *applyRun, k rowKey, f hostFields, target string) error {
	run.markWrite()
	id, err := p.client.AddHostOverride(ctx, f)
	if err != nil {
		return fmt.Errorf("add %s %s -> %s: %w", k.rr, k.name, target, err)
	}
	run.addRow(hostRow{
		UUID: id, Enabled: f.Enabled, Hostname: f.Hostname, Domain: f.Domain, RR: f.RR,
		Server: f.Server, TXTData: f.TXTData, TTL: f.TTL, AddPTR: f.AddPTR, Description: f.Description,
	})
	metrics.Get().RecordChange("create", k.rr)
	slog.Info("created override", "name", k.name, "type", k.rr, "target", target, "uuid", id)
	return nil
}

func hasEnabledChildren(r *hostRow) bool {
	for _, c := range r.Children {
		if c.enabled() {
			return true
		}
	}
	return false
}

// fields builds the write body for one row.
func (p *Provider) fields(host, domain, rr, target string, ttl int64) hostFields {
	f := hostFields{Enabled: "1", Hostname: host, Domain: domain, RR: rr, TTL: ttlField(ttl), AddPTR: "0", Description: p.cfg.OwnerMarker}
	if p.cfg.AddPTR {
		f.AddPTR = "1"
	}
	if rr == recordTypeTXT {
		f.TXTData = target
		f.AddPTR = "0"
	} else {
		f.Server = target
	}
	return f
}

func sortedTargets(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for t := range m {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
