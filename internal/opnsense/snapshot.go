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
	rows     []hostRow
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

func buildSnapshot(rows []hostRow, total int) *Snapshot {
	s := &Snapshot{Total: total, rows: rows, byKey: map[rowKey][]*hostRow{}, byTarget: map[rowKey]map[string]*hostRow{}}
	for i := range s.rows {
		s.index(&s.rows[i])
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

// add records a row the apply path just created.
//
//nolint:unused // consumed by ApplyChanges in a later task
func (s *Snapshot) add(r hostRow) {
	s.rows = append(s.rows, r)
	s.index(&s.rows[len(s.rows)-1])
}

// remove forgets a row the apply path just deleted.
//
//nolint:unused // consumed by ApplyChanges in a later task
func (s *Snapshot) remove(k rowKey, uuid string) {
	kept := s.byKey[k][:0]
	for _, r := range s.byKey[k] {
		if r.UUID != uuid {
			kept = append(kept, r)
		} else {
			delete(s.byTarget[k], r.bareTarget())
		}
	}
	s.byKey[k] = kept
}

//nolint:unused // consumed by ApplyChanges in a later task
func (s *Snapshot) rowsFor(k rowKey) []*hostRow { return s.byKey[k] }

type group struct {
	targets []string
	ttl     int64
	set     bool
}

func (g *group) add(target string, ttl int64) {
	g.targets = append(g.targets, target)
	if !g.set || ttl < g.ttl {
		g.ttl = ttl
		g.set = true
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
	for i := range s.rows {
		r := &s.rows[i]
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
		out = append(out, endpoint.NewEndpointWithTTL(k.name, k.rr, endpoint.TTL(g.ttl), g.targets...))
	}
	return out
}
