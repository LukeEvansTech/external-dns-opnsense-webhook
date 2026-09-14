package opnsense

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"

	"github.com/LukeEvansTech/external-dns-opnsense-webhook/internal/metrics"
	"sigs.k8s.io/external-dns/endpoint"
)

// rowKey identifies a record set: normalised FQDN plus record type. A struct
// key cannot collide the way name+type string concatenation can.
type rowKey struct {
	name string
	rr   string
}

// Snapshot is one consistent read of the host override table with the
// indexes the apply path needs. Only enabled, non-alias, top-level rows are
// indexed; disabled rows and children are kept on rows for reads.
type Snapshot struct {
	Total    int
	rows     []*hostRow
	byKey    map[rowKey][]*hostRow
	byTarget map[rowKey]map[string]*hostRow
}

// Snapshot pages through searchHostOverride under the consistency rules:
// total constant across pages, no empty page before the end, page count
// bounded, unique uuid count equal to total. Otherwise the read restarts, up
// to ReadAttempts, then fails. A partial table is never returned.
func (c *Client) Snapshot(ctx context.Context) (*Snapshot, error) {
	var lastErr error
	for attempt := 0; attempt < c.cfg.ReadAttempts; attempt++ {
		if attempt > 0 {
			metrics.Get().ReadRestartsTotal.WithLabelValues(metrics.ProviderName).Inc()
			slog.Warn("restarting host override read", "attempt", attempt+1, "reason", lastErr)
		}
		rows, total, err := c.readAll(ctx)
		if err == nil {
			return buildSnapshot(rows, total), nil
		}
		if !isInconsistent(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("%w after %d attempts: %v", ErrInconsistentRead, c.cfg.ReadAttempts, lastErr)
}

type inconsistentError struct{ reason string }

func (e *inconsistentError) Error() string        { return "opnsense: inconsistent read: " + e.reason }
func (e *inconsistentError) Is(target error) bool { return target == ErrInconsistentRead }

func isInconsistent(err error) bool {
	_, ok := errors.AsType[*inconsistentError](err)
	return ok
}

func (c *Client) readAll(ctx context.Context) ([]hostRow, int, error) {
	pageSize := c.cfg.PageSize
	seen := make(map[string]struct{})
	var rows []hostRow
	total := -1
	for current := 1; ; current++ {
		page, err := c.SearchHostOverrides(ctx, current, pageSize)
		if err != nil {
			return nil, 0, err
		}
		switch {
		case total < 0:
			total = page.Total
		case page.Total != total:
			return nil, 0, &inconsistentError{fmt.Sprintf("total changed from %d to %d on page %d", total, page.Total, current)}
		}
		if total == 0 {
			return nil, 0, nil
		}
		maxPages := (total+pageSize-1)/pageSize + 1
		if current > maxPages {
			return nil, 0, &inconsistentError{fmt.Sprintf("more than %d pages for total %d", maxPages, total)}
		}
		if len(page.Rows) == 0 {
			if len(seen) == total {
				break
			}
			return nil, 0, &inconsistentError{fmt.Sprintf("empty page %d with %d of %d rows collected", current, len(seen), total)}
		}
		for _, r := range page.Rows {
			if _, dup := seen[r.UUID]; dup {
				continue
			}
			seen[r.UUID] = struct{}{}
			rows = append(rows, r)
		}
		if len(seen) > total {
			return nil, 0, &inconsistentError{fmt.Sprintf("%d unique rows exceed total %d", len(seen), total)}
		}
		if len(seen) == total {
			break
		}
	}
	if len(rows) != total {
		return nil, 0, &inconsistentError{fmt.Sprintf("collected %d rows, total %d", len(rows), total)}
	}
	return rows, total, nil
}

// buildSnapshot takes ownership of rows (the caller does not reuse it) and
// indexes pointers into it, not into s.rows: s.rows is its own []*hostRow,
// so a later add growing it can never move rows's elements and invalidate
// the pointers held in byKey/byTarget.
func buildSnapshot(rows []hostRow, total int) *Snapshot {
	s := &Snapshot{
		Total:    total,
		rows:     make([]*hostRow, len(rows)),
		byKey:    map[rowKey][]*hostRow{},
		byTarget: map[rowKey]map[string]*hostRow{},
	}
	for i := range rows {
		s.rows[i] = &rows[i]
		s.index(s.rows[i])
	}
	return s
}

// bareTarget is the target as compared on write: server for A/AAAA, the
// stored (unquoted) txtdata for TXT.
func (r *hostRow) bareTarget() string {
	if r.RR == recordTypeTXT {
		return r.TXTData
	}
	return r.Server
}

func (s *Snapshot) index(r *hostRow) {
	if !r.enabled() || bool(r.IsAlias) {
		return
	}
	k := rowKey{name: joinName(r.Hostname, r.Domain), rr: r.RR}
	s.byKey[k] = append(s.byKey[k], r)
	if s.byTarget[k] == nil {
		s.byTarget[k] = map[string]*hostRow{}
	}
	s.byTarget[k][r.bareTarget()] = r
}

// add records a row the apply path just created. r is copied onto the heap
// once (p := &r) and that pointer, not an index into s.rows, is what gets
// appended and indexed, so a later append growing s.rows never moves it.
func (s *Snapshot) add(r hostRow) {
	p := &r
	s.rows = append(s.rows, p)
	s.index(p)
}

// remove forgets a row the apply path just deleted. It compacts byKey[k] in
// place and clears the now-unused tail so the removed row's pointer is not
// kept alive by a stale slice element. rowsFor aliases this same backing
// array, so a caller that deletes while iterating rowsFor's result must
// iterate a copy, not the slice rowsFor returned.
func (s *Snapshot) remove(k rowKey, uuid string) {
	kept := s.byKey[k][:0]
	for _, r := range s.byKey[k] {
		if r.UUID != uuid {
			kept = append(kept, r)
		} else {
			delete(s.byTarget[k], r.bareTarget())
		}
	}
	clear(s.byKey[k][len(kept):])
	s.byKey[k] = kept
}

// rowsFor returns the rows for k. The slice aliases byKey's backing array,
// which remove compacts in place: a caller that calls remove while iterating
// this result must iterate a copy instead.
func (s *Snapshot) rowsFor(k rowKey) []*hostRow { return s.byKey[k] }

// group accumulates one (name, type) record set while Endpoints folds rows.
// ttl 0 means unset (hostRow.ttlValue's zero value): an unset row is ignored
// once any row in the group carries an explicit TTL, so the smallest
// explicit TTL wins and the group's TTL is 0 only when every row is unset.
// differs records whether the rows disagreed at all — explicit values that
// differ from each other, or a mix of unset and explicit — which Endpoints
// warns about once per key.
type group struct {
	targets  []string
	ttl      int64
	haveTTL  bool
	sawUnset bool
	differs  bool
}

func (g *group) add(target string, ttl int64) {
	g.targets = append(g.targets, target)
	if ttl == 0 {
		g.sawUnset = true
		if g.haveTTL {
			g.differs = true
		}
		return
	}
	switch {
	case !g.haveTTL:
		g.ttl = ttl
		g.haveTTL = true
		if g.sawUnset {
			g.differs = true
		}
	case ttl != g.ttl:
		g.differs = true
		if ttl < g.ttl {
			g.ttl = ttl
		}
	}
}

// Endpoints maps the snapshot to external-dns endpoints. Aliases become
// records of the parent's type at the alias name, which is what unbound.inc
// serves; they carry no registry TXT so external-dns leaves them alone.
func (s *Snapshot) Endpoints() []*endpoint.Endpoint {
	groups := map[rowKey]*group{}
	put := func(name, rr, target string, ttl int64) {
		k := rowKey{name: name, rr: rr}
		if groups[k] == nil {
			groups[k] = &group{}
		}
		groups[k].add(target, ttl)
	}
	for _, r := range s.rows {
		if !r.enabled() || bool(r.IsAlias) {
			continue
		}
		switch r.RR {
		case recordTypeA, recordTypeAAAA, recordTypeTXT, recordTypeMX:
		default:
			slog.Debug("skipping row with unsupported rr", "uuid", r.UUID, "rr", r.RR)
			continue
		}
		name := joinName(r.Hostname, r.Domain)
		put(name, r.RR, r.target(), r.ttlValue())
		// Every _children entry is emitted as a record of its parent's type
		// at the alias name: DESIGN 6.1 only spells this out for A/AAAA
		// parents, but unbound.inc renders an alias as a copy of whatever
		// row it hangs off, TXT and MX included, so this loop does the same
		// for every rr this provider maps (the switch above already limited
		// r.RR to that set).
		for _, child := range r.Children {
			if !child.enabled() {
				continue
			}
			host, domain := child.Hostname, child.Domain
			if host == "" {
				host = r.Hostname
			}
			if domain == "" {
				domain = r.Domain
			}
			put(joinName(host, domain), r.RR, r.target(), r.ttlValue())
		}
	}
	keys := make([]rowKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		return keys[i].rr < keys[j].rr
	})
	out := make([]*endpoint.Endpoint, 0, len(keys))
	for _, k := range keys {
		g := groups[k]
		sort.Strings(g.targets)
		if g.differs {
			slog.Warn("grouped rows have different TTLs; using the smallest explicit value", "name", k.name, "rr", k.rr, "ttl", g.ttl)
		}
		out = append(out, endpoint.NewEndpointWithTTL(k.name, k.rr, endpoint.TTL(g.ttl), g.targets...))
	}
	return out
}
