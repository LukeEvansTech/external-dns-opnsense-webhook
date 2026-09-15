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
// targets are stored bare (quotes stripped) so they compare with rows. host
// and domain are the key's name split against the configured domains, done
// once here so the converge path never has to repeat it.
type desiredSet struct {
	key     rowKey
	host    string
	domain  string
	targets map[string]struct{}
	ttl     int64
	// failed records that the add/set phase for this key did not write every
	// desired target, either because a write failed or because the phase was
	// gated out. The remove phase then leaves the key's surplus rows alone:
	// dropping them would shrink a record set the plan meant to grow or
	// replace, and could leave the name resolving to nothing.
	failed bool
}

type convergeMode int

const (
	modeAddSet convergeMode = iota
	modeRemove
)

// Phase indices into applyPhases; gatedOn refers to them by name.
const (
	phaseTXTAdd = iota
	phaseDataAdd
	phaseDataRemove
	phaseTXTRemove
)

// noGate marks a phase that runs unconditionally.
const noGate = -1

// Change operations: the operation label on the change and lost-write
// counters, and the kind of a recorded write.
const (
	changeCreate = "create"
	changeUpdate = "update"
	changeDelete = "delete"
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
var applyPhases = [...]struct {
	selects func(rr string) bool
	mode    convergeMode
	gatedOn int
	skip    string
}{
	phaseTXTAdd:     {isTXT, modeAddSet, noGate, ""},
	phaseDataAdd:    {isData, modeAddSet, phaseTXTAdd, "skipping data creates: TXT writes failed or were rejected this cycle"},
	phaseDataRemove: {isData, modeRemove, noGate, ""},
	phaseTXTRemove:  {isTXT, modeRemove, phaseDataRemove, "skipping TXT removes: data deletes failed this cycle"},
}

// applyRun is the mutable state of one ApplyChanges. mu guards all of it, the
// snapshot index included: several keys converge concurrently and every one of
// them can add or remove rows. Nothing reads a field of this struct without
// taking mu; the accessors below are the only way in.
//
// The snapshot's rows are read and written outside mu. That is safe because a
// phase gives each rowKey to exactly one goroutine, and a row belongs to
// exactly one rowKey, so no two workers ever touch the same *hostRow; only the
// index they hang off is shared, and every path into it takes mu.
type applyRun struct {
	p    *Provider
	snap *Snapshot
	sets map[rowKey]*desiredSet

	mu    sync.Mutex
	errs  []error
	wrote bool
	// phaseFailed counts converge failures within the phase now running; apply
	// resets it before each phase and reads it once the phase has drained.
	phaseFailed int
	// writes lists every write the firewall acknowledged in the phase now
	// running; verifyPhase takes and checks them once the phase has drained.
	writes []writeRecord
}

// writeRecord is one acknowledged write and the state the table must show
// for it once re-read: the row present and reading as want (create and
// update), or absent (delete, where want is unused).
type writeRecord struct {
	op   string
	key  rowKey
	uuid string
	want hostFields
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

// markFailed records that a key's desired targets were never attempted — the
// phase that would have written them was gated out. A key with no targets is
// a delete and is left alone: its removal is the whole point of the plan and
// nothing protective was skipped on its behalf.
func (r *applyRun) markFailed(set *desiredSet) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(set.targets) > 0 {
		set.failed = true
	}
}

// lost records a write the re-read did not show and marks its key failed, so
// the later phases treat the key exactly as they would after a rejected write.
func (r *applyRun) lost(set *desiredSet, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, err)
	if set != nil {
		set.failed = true
	}
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

func (r *applyRun) didWrite() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.wrote
}

func (r *applyRun) addErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, err)
}

// record logs a write the firewall acknowledged, for verifyPhase.
func (r *applyRun) record(op string, k rowKey, uuid string, want hostFields) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes = append(r.writes, writeRecord{op: op, key: k, uuid: uuid, want: want})
}

// takeWrites hands back the phase's acknowledged writes and clears the log.
func (r *applyRun) takeWrites() []writeRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	w := r.writes
	r.writes = nil
	return w
}

// err joins everything collected during the run.
func (r *applyRun) err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return errors.Join(r.errs...)
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
// the only index the apply path consults, and a write never moves a row
// between keys — the panic below states that invariant rather than trusting
// it, because a row that silently changed key would be indexed under the old
// one and leak past every later phase.
func (r *applyRun) retarget(k rowKey, row *hostRow, f hostFields) {
	if got := (rowKey{name: joinName(f.Hostname, f.Domain), rr: f.RR}); got != k {
		panic(fmt.Sprintf("opnsense: write would move row %s from %v to %v", row.UUID, k, got))
	}
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
//
// The third return is how many distinct keys were dropped for an invalid TXT
// target. Those keys never reach a phase, so apply counts them against the TXT
// add/set phase instead: a registry row rejected here is as absent as one whose
// write failed, and invariant I1 holds either way.
//
// Two endpoints can name the same key. Identical content is harmless — the
// second is simply redundant — but two that disagree describe a plan with no
// single answer, so both are dropped with an error rather than letting
// whichever the map iteration reached last silently win.
func (p *Provider) foldChanges(changes *plan.Changes) (map[rowKey]*desiredSet, []error, int) {
	sets := map[rowKey]*desiredSet{}
	conflicted := map[rowKey]bool{}
	rejectedTXT := map[rowKey]bool{}
	var errs []error

	define := func(e *endpoint.Endpoint, empty bool) {
		name := normaliseName(e.DNSName)
		host, domain, err := splitName(name, p.cfg.Domains)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", e.RecordType, name, err))
			return
		}
		if !empty && len(e.Targets) == 0 {
			errs = append(errs, fmt.Errorf("%s %s: no targets", e.RecordType, name))
			return
		}
		k := rowKey{name: name, rr: e.RecordType}
		if conflicted[k] {
			return
		}
		set := &desiredSet{key: k, host: host, domain: domain, targets: map[string]struct{}{}, ttl: clampTTL(e.RecordTTL)}
		for _, t := range e.Targets {
			if empty {
				break
			}
			switch e.RecordType {
			case recordTypeA, recordTypeAAAA:
				set.targets[t] = struct{}{}
			case recordTypeTXT:
				bare, terr := validateTXT(t)
				if terr != nil {
					metrics.Get().TXTInvalidTotal.WithLabelValues(metrics.ProviderName).Inc()
					errs = append(errs, fmt.Errorf("TXT %s: %w", name, terr))
					rejectedTXT[k] = true
					return
				}
				set.targets[bare] = struct{}{}
			default:
				errs = append(errs, fmt.Errorf("%s %s: %w", e.RecordType, name, ErrUnsupportedType))
				return
			}
		}
		if prev, dup := sets[k]; dup && !sameSet(prev, set) {
			errs = append(errs, fmt.Errorf("%s %s: the plan describes this record two ways", e.RecordType, name))
			delete(sets, k)
			conflicted[k] = true
			return
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
	return sets, errs, len(rejectedTXT)
}

// sameSet reports whether two definitions of one key ask for the same thing.
func sameSet(a, b *desiredSet) bool {
	if a.ttl != b.ttl || len(a.targets) != len(b.targets) {
		return false
	}
	for t := range a.targets {
		if _, ok := b.targets[t]; !ok {
			return false
		}
	}
	return true
}

// apply runs the four phases from the design: TXT add/set, data add/set, data
// remove, TXT remove. Each phase drains before the next so a data row never
// exists without its TXT row across a failure boundary. A TXT target the fold
// rejected is counted as a failure of the TXT add/set phase before the phases
// run, so the same gate that holds after a failed registry write also holds
// after an invalid one.
func (p *Provider) apply(ctx context.Context, changes *plan.Changes) error {
	snap, err := p.client.Snapshot(ctx)
	if err != nil {
		return err
	}
	sets, errs, rejectedTXT := p.foldChanges(changes)
	run := &applyRun{p: p, snap: snap, sets: sets, errs: errs}

	keys := make([]rowKey, 0, len(sets))
	for k := range sets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].name < keys[j].name })

	// Seeded, not assigned in the loop: a key the fold dropped for an invalid
	// TXT target is not in sets at all, so the TXT phase can only ever report
	// zero failures for it, and the data rows it was to claim would be created
	// with nothing recording who owns them.
	failures := make([]int, len(applyPhases))
	failures[phaseTXTAdd] = rejectedTXT
	for i, ph := range applyPhases {
		selected := make([]*desiredSet, 0, len(keys))
		for _, k := range keys {
			if ph.selects(k.rr) {
				selected = append(selected, sets[k])
			}
		}
		if ph.gatedOn != noGate && failures[ph.gatedOn] > 0 {
			slog.Warn(ph.skip, "failures", failures[ph.gatedOn], "keys", len(selected))
			// The targets this phase would have written were never attempted,
			// so the matching remove phase must not treat the rows they were
			// meant to replace as surplus.
			for _, set := range selected {
				run.markFailed(set)
			}
			continue
		}
		run.startPhase()
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(p.cfg.ApplyWorkers)
		for _, set := range selected {
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
		failures[i] += run.endPhase()
		// A write the firewall acknowledged but did not keep counts against
		// this phase like a rejected one, so the same gate protects the next.
		failures[i] += p.verifyPhase(ctx, run)
	}

	// A write attempt, committed or not, means saved and served may differ; so
	// does a reconfigure an earlier apply could not complete. Either way the
	// firewall is reloaded here rather than left waiting for the next read.
	if run.didWrite() || p.pending.Load() {
		if rerr := p.reconfigure(false); rerr != nil {
			run.addErr(fmt.Errorf("reconfigure: %w", rerr))
		}
	}
	return run.err()
}

// verifyPhase re-reads the table after a phase that wrote and checks every
// acknowledged write is really there: a created or updated row exists and
// reads as written, a deleted row is gone. OPNsense has answered "saved" for
// rows that never reached the config, so an acknowledgement alone is not
// proof the write landed. Each lost write is logged, counted, and recorded
// against its key as a failure, which is what lets the phase gate and the
// remove phases treat it like a rejected write; the rows that did land are
// still reconfigured. The read is a safety net, not a gate: if it fails, that
// is logged and the apply carries on.
//
// A present row is compared on exactly the fields addSet compares when it
// decides a row needs no write, so a row this accepts is one the next apply
// would leave alone.
//
// It returns how many writes were lost.
func (p *Provider) verifyPhase(ctx context.Context, run *applyRun) int {
	writes := run.takeWrites()
	if len(writes) == 0 {
		return 0
	}
	snap, err := p.client.Snapshot(ctx)
	if err != nil {
		slog.Error("post-phase verification read failed; lost writes cannot be detected this cycle", "writes", len(writes), "error", err)
		return 0
	}
	byUUID := make(map[string]*hostRow, len(snap.rows))
	for _, r := range snap.rows {
		byUUID[r.UUID] = r
	}
	lost := 0
	for _, w := range writes {
		row, present := byUUID[w.uuid]
		var problem string
		switch {
		case w.op == changeDelete:
			if present {
				problem = "row still present"
			}
		case !present:
			problem = "row missing"
		default:
			problem = row.differsFrom(w.want)
		}
		if problem == "" {
			continue
		}
		lost++
		metrics.Get().LostWritesTotal.WithLabelValues(metrics.ProviderName, w.op).Inc()
		slog.Error("write acknowledged by OPNsense but not saved", "operation", w.op, "name", w.key.name, "type", w.key.rr, "uuid", w.uuid, "problem", problem)
		run.lost(run.sets[w.key], fmt.Errorf("%s %s %s (%s): %w: %s", w.op, w.key.rr, w.key.name, w.uuid, ErrLostWrite, problem))
	}
	return lost
}

// differsFrom reports the first way the row does not read as the write want
// described it, or "" when it does.
func (r *hostRow) differsFrom(want hostFields) string {
	switch {
	case joinName(r.Hostname, r.Domain) != joinName(want.Hostname, want.Domain) || r.RR != want.RR:
		return fmt.Sprintf("row reads %s %s", r.RR, joinName(r.Hostname, r.Domain))
	case r.bareTarget() != want.target():
		return fmt.Sprintf("target reads %q", r.bareTarget())
	case r.ttlValue() != parseTTL(want.TTL):
		return fmt.Sprintf("ttl reads %q", r.TTL)
	case r.Description != want.Description:
		return fmt.Sprintf("description reads %q", r.Description)
	case r.AddPTR != want.AddPTR:
		return fmt.Sprintf("addptr reads %q", r.AddPTR)
	}
	return ""
}

// converge brings one key's rows towards its desired set in the given mode.
func (p *Provider) converge(ctx context.Context, run *applyRun, set *desiredSet, mode convergeMode) error {
	existing := run.rows(set.key)
	if mode == modeRemove {
		return p.removeSurplus(ctx, run, set, existing)
	}
	return p.addSet(ctx, run, set, existing)
}

// addSet makes every desired target present: rows already carrying one are
// brought into line, rows the plan no longer wants are reused for the targets
// that have none, and only what is still missing is created.
func (p *Provider) addSet(ctx context.Context, run *applyRun, set *desiredSet, existing []*hostRow) error {
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
		f := p.fields(set, t)
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
		if err := p.setRow(ctx, run, set.key, surplus[i], p.fields(set, missing[i]), missing[i]); err != nil {
			return err
		}
	}
	for _, t := range missing[reused:] {
		if err := p.createRow(ctx, run, set.key, p.fields(set, t), t); err != nil {
			return err
		}
	}
	return nil
}

// removeSurplus deletes the key's rows the desired set no longer names.
//
// A blocked row stops the whole key rather than only itself. That is
// deliberate: a name whose rows carry hand-made aliases freezes in its current
// shape until an operator deals with the alias, which is safer than shrinking
// the record set halfway and serving an answer nobody asked for.
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
		run.record(changeDelete, set.key, r.UUID, hostFields{})
		if deleted {
			metrics.Get().RecordChange(changeDelete, set.key.rr)
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
		return fmt.Errorf("set %s %s -> %s (%s): %w", k.rr, k.name, target, r.UUID, err)
	}
	run.retarget(k, r, f)
	run.record(changeUpdate, k, r.UUID, f)
	metrics.Get().RecordChange(changeUpdate, k.rr)
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
	run.record(changeCreate, k, id, f)
	metrics.Get().RecordChange(changeCreate, k.rr)
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

// fields builds the write body for one of the set's targets.
func (p *Provider) fields(set *desiredSet, target string) hostFields {
	f := hostFields{
		Enabled: "1", Hostname: set.host, Domain: set.domain, RR: set.key.rr,
		TTL: ttlField(set.ttl), AddPTR: "0", Description: p.cfg.OwnerMarker,
	}
	if p.cfg.AddPTR {
		f.AddPTR = "1"
	}
	if set.key.rr == recordTypeTXT {
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
