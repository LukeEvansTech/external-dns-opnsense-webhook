//go:build reconcile

package reconcile

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LukeEvansTech/external-dns-opnsense-webhook/test/fake"
	"sigs.k8s.io/external-dns/endpoint"
)

// Scenarios use the harness, registry and converge helpers from harness_test.go.

const (
	appName = "app.example.com"
	// appTXTName is where k8s.main.%{record_type}- puts the registry's
	// ownership record for appName, and txtRowHost is the hostname half of
	// that name once it is split against OPNSENSE_DOMAINS.
	appTXTName = "k8s.main.a-app.example.com"
	txtRowHost = "k8s.main.a-app"

	foreignTXTName = "k8s.main.a-theirs.example.com"
	recordTypeTXT  = "TXT"

	// foreignMarker is the description on the rows another controller owns.
	// Deliberately not "external-dns", the default OPNSENSE_OWNER_MARKER the
	// binary runs with: sharing the marker would make these rows look managed
	// to the startup served-state check, and would leave it ambiguous whether
	// they survive a scenario because the planner respects the foreign owner
	// label or merely because nothing happened to touch them.
	foreignMarker = "other-external-dns"

	readyWithin = 10 * time.Second
)

func a(name string, ttl int64, targets ...string) *endpoint.Endpoint {
	return endpoint.NewEndpointWithTTL(name, endpoint.RecordTypeA, endpoint.TTL(ttl), targets...)
}

type fixtures struct {
	handRow   fake.Row
	handAlias fake.Alias
	foreign   fake.Row
}

// seed installs the rows every scenario must leave untouched: a hand-made row
// with a hand-made alias hanging off it, and a record pair owned by another
// external-dns instance.
func seed(t *testing.T, f *fake.Server) fixtures {
	t.Helper()
	id := f.AddRow(fake.Row{Hostname: "nas", Domain: "example.com", RR: "A", Server: "192.0.2.50", Description: "device"})
	f.AddAlias(id, "files", "")
	f.AddRow(fake.Row{
		Hostname: "k8s.main.a-theirs", Domain: "example.com", RR: recordTypeTXT,
		TXTData: "heritage=external-dns,external-dns/owner=other", Description: foreignMarker,
	})
	f.AddRow(fake.Row{
		Hostname: "theirs", Domain: "example.com", RR: "A",
		Server: "192.0.2.60", Description: foreignMarker,
	})
	f.Reconfigure()
	rows, aliases := f.Rows(), f.Aliases()
	return fixtures{handRow: rows[0], handAlias: aliases[0], foreign: rows[1]}
}

// untouchedProblems reports every way the protected objects differ from the
// fixtures, in both the config table and the served table. It returns the
// problems rather than failing so TestReconcile_UntouchedControl can prove
// each branch fires.
func untouchedProblems(f *fake.Server, fx fixtures) []string {
	var problems []string
	var hand, foreign *fake.Row
	for _, r := range f.Rows() {
		switch r.UUID {
		case fx.handRow.UUID:
			hand = &r
		case fx.foreign.UUID:
			foreign = &r
		}
	}
	if hand == nil || !reflect.DeepEqual(*hand, fx.handRow) {
		problems = append(problems, fmt.Sprintf("hand-made row changed: %+v", hand))
	}
	if foreign == nil || !reflect.DeepEqual(*foreign, fx.foreign) {
		problems = append(problems, fmt.Sprintf("foreign-owned TXT changed: %+v", foreign))
	}
	if len(f.Aliases()) != 1 || f.Aliases()[0] != fx.handAlias {
		problems = append(problems, fmt.Sprintf("hand-made alias changed: %+v", f.Aliases()))
	}
	// The served table has to agree: the hand-made row, the alias copy of it
	// and the foreign-owned pair must all still be published.
	for _, want := range []struct{ name, rr, value string }{
		{"nas.example.com", "A", "192.0.2.50"},
		{"files.example.com", "A", "192.0.2.50"},
		{"theirs.example.com", "A", "192.0.2.60"},
	} {
		if !servedHas(f, want.name, want.rr, want.value) {
			problems = append(problems, fmt.Sprintf("%s %s %s no longer served", want.name, want.rr, want.value))
		}
	}
	if !txtServed(f, foreignTXTName) {
		problems = append(problems, "foreign-owned TXT no longer served")
	}
	return problems
}

func assertUntouched(t *testing.T, f *fake.Server, fx fixtures) {
	t.Helper()
	for _, p := range untouchedProblems(f, fx) {
		t.Errorf("%s (served: %+v)", p, f.Served())
	}
}

func servedHas(f *fake.Server, name, rr, value string) bool {
	for _, s := range f.Served() {
		if s.Name == name+"." && s.RRType == rr && s.Value == value {
			return true
		}
	}
	return false
}

func txtServed(f *fake.Server, name string) bool {
	for _, s := range f.Served() {
		if s.Name == name+"." && s.RRType == recordTypeTXT {
			return true
		}
	}
	return false
}

// txtRows counts the registry's ownership rows for appName in the config table.
func txtRows(f *fake.Server) int {
	n := 0
	for _, r := range f.Rows() {
		if r.Hostname == txtRowHost && r.RR == recordTypeTXT {
			n++
		}
	}
	return n
}

// TestReconcile_UntouchedControl is the known-bad control for
// untouchedProblems: the assertion every other test leans on has to be shown
// to fire, or "nothing unrelated changed" is just a checker that examined
// nothing.
//
// untouchedProblems has five branches. Four are proved in isolation — a case
// breaks exactly one and the others stay green:
//
//	hand-made row edited  -> the hand-made row's DeepEqual branch
//	foreign TXT deleted   -> the foreign row's DeepEqual branch
//	hand-made alias added -> the alias count/equality branch
//	served A row dropped  -> the served-table branch, via the "theirs" A row,
//	                         which no config-table branch looks at
//
// The fifth, "the foreign-owned TXT is no longer served", has no isolated
// case and cannot have one: the fake derives its served table from its config
// table, so the only ways to unpublish that row (delete it, or disable it)
// both change the row itself and therefore trip the DeepEqual branch too. The
// last case below fires it together with that branch, which still proves the
// check is reachable and wired to the served table rather than dead.
func TestReconcile_UntouchedControl(t *testing.T) {
	post := func(t *testing.T, f *fake.Server, path, body string) {
		t.Helper()
		resp, err := http.Post(f.URL()+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	del := func(t *testing.T, f *fake.Server, uuid string) {
		t.Helper()
		post(t, f, "/api/unbound/settings/delHostOverride/"+uuid, `{}`)
	}
	cases := []struct {
		name string
		// wantIsolated is the number of problems the break must produce: 1
		// for the four isolated branches, 2 for the served-TXT case that
		// cannot be isolated.
		wantIsolated int
		mutate       func(t *testing.T, f *fake.Server, fx fixtures)
	}{
		{"hand-made row edited", 1, func(t *testing.T, f *fake.Server, fx fixtures) {
			post(t, f, "/api/unbound/settings/setHostOverride/"+fx.handRow.UUID,
				`{"host":{"hostname":"nas","domain":"example.com","rr":"A","server":"198.51.100.1"}}`)
		}},
		{"foreign TXT deleted", 1, func(t *testing.T, f *fake.Server, fx fixtures) {
			del(t, f, fx.foreign.UUID)
		}},
		{"hand-made alias added", 1, func(_ *testing.T, f *fake.Server, fx fixtures) {
			f.AddAlias(fx.handRow.UUID, "extra", "")
		}},
		{"served A row dropped", 1, func(t *testing.T, f *fake.Server, _ fixtures) {
			// "theirs" is in the served-table list and in no config-table
			// check, so deleting it and republishing reddens the served
			// branch alone.
			for _, r := range f.Rows() {
				if r.Hostname == "theirs" {
					del(t, f, r.UUID)
				}
			}
			f.Reconfigure()
		}},
		{"foreign TXT unpublished", 2, func(t *testing.T, f *fake.Server, fx fixtures) {
			del(t, f, fx.foreign.UUID)
			f.Reconfigure()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fake.New(t)
			fx := seed(t, f)
			if got := untouchedProblems(f, fx); len(got) != 0 {
				t.Fatalf("untouched table reported problems: %v", got)
			}
			tc.mutate(t, f, fx)
			got := untouchedProblems(f, fx)
			if len(got) != tc.wantIsolated {
				t.Errorf("after %s: %d problems %v, want %d", tc.name, len(got), got, tc.wantIsolated)
			}
		})
	}
}

func TestReconcile_Lifecycle(t *testing.T) {
	h := newHarness(t)
	fx := seed(t, h.fake)
	h.waitForReady(readyWithin)
	reg := newRegistry(t, h.webhookURL)
	// The TXT value carries the resource label the registry writes; the test
	// asserts presence, not content.

	desired := []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")}
	converge(t, reg, desired, 3)
	if !servedHas(h.fake, appName, "A", "192.0.2.1") || !txtServed(h.fake, appTXTName) {
		t.Fatalf("create not served: %+v", h.fake.Served())
	}
	if n := txtRows(h.fake); n != 1 {
		t.Fatalf("TXT rows for app after create = %d, want 1", n)
	}
	assertUntouched(t, h.fake, fx)

	converge(t, reg, []*endpoint.Endpoint{a(appName, 300, "192.0.2.2")}, 3)
	if !servedHas(h.fake, appName, "A", "192.0.2.2") || servedHas(h.fake, appName, "A", "192.0.2.1") {
		t.Fatalf("update not served: %+v", h.fake.Served())
	}
	assertUntouched(t, h.fake, fx)

	converge(t, reg, []*endpoint.Endpoint{a(appName, 300, "192.0.2.2", "192.0.2.3")}, 3)
	if !servedHas(h.fake, appName, "A", "192.0.2.3") {
		t.Fatalf("second target not served: %+v", h.fake.Served())
	}
	converge(t, reg, []*endpoint.Endpoint{a(appName, 300, "192.0.2.3")}, 3)
	if servedHas(h.fake, appName, "A", "192.0.2.2") {
		t.Fatalf("removed target still served: %+v", h.fake.Served())
	}
	if n := txtRows(h.fake); n != 1 {
		t.Fatalf("TXT rows for app after multi-target churn = %d, want 1", n)
	}
	assertUntouched(t, h.fake, fx)

	converge(t, reg, nil, 3)
	if servedHas(h.fake, appName, "A", "192.0.2.3") || txtServed(h.fake, appTXTName) {
		t.Fatalf("delete not served: %+v", h.fake.Served())
	}
	if n := txtRows(h.fake); n != 0 {
		t.Fatalf("TXT rows for app after delete = %d, want 0", n)
	}
	assertUntouched(t, h.fake, fx)
	if !servedHas(h.fake, "theirs.example.com", "A", "192.0.2.60") {
		t.Error("foreign-owned record removed")
	}
}

func TestReconcile_Faults(t *testing.T) {
	cases := []struct {
		name string
		// op is the fake operation the fault is armed on. The case asserts it
		// was called after arming, so a fault that never had the chance to
		// fire cannot pass as a converged scenario.
		op     string
		arm    func(f *fake.Server)
		before []*endpoint.Endpoint
		after  []*endpoint.Endpoint
		// wantTXTRows is how many registry rows for appName the converged
		// config table must hold. It is stated per case rather than derived
		// from after, because one fault leaves an orphan the controller
		// cannot reach (see the note on the delete case), and the served
		// table is checked against it: the registry row is published exactly
		// when the config table holds it.
		wantTXTRows int
		// minReconfigures is the floor on successful publishes, counting the
		// one seed does. It matters most in the reconfigure case, where the
		// apply's own reload fails and only the repair-on-read path in
		// Records() can get the count to two.
		minReconfigures int
	}{
		{
			name: "txt ok then A add fails",
			op:   fake.OpAddHostOverride,
			arm: func(f *fake.Server) {
				f.Inject(fake.Fault{Op: fake.OpAddHostOverride, Status: 500, Times: 1, SkipCalls: 1})
			},
			after:           []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")},
			wantTXTRows:     1,
			minReconfigures: 2,
		},
		{
			name: "A add committed, response lost",
			op:   fake.OpAddHostOverride,
			arm: func(f *fake.Server) {
				f.Inject(fake.Fault{Op: fake.OpAddHostOverride, Status: 502, Times: 1, SkipCalls: 1, AfterCommit: true})
			},
			after:           []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")},
			wantTXTRows:     1,
			minReconfigures: 2,
		},
		{
			name:            "partial update",
			op:              fake.OpSet,
			arm:             func(f *fake.Server) { f.Inject(fake.Fault{Op: fake.OpSet, Status: 500, Times: 1}) },
			before:          []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")},
			after:           []*endpoint.Endpoint{a(appName, 600, "192.0.2.1")},
			wantTXTRows:     1,
			minReconfigures: 2,
		},
		{
			// The data row goes (phase 3) and the registry row does not
			// (phase 4 fails), which is the one fault in this table that does
			// not converge to a clean table. It is not a provider defect and
			// no further reconcile can fix it: the TXT registry folds every
			// heritage-bearing TXT into its ownership map instead of
			// returning it as an endpoint, so the planner never sees a record
			// to delete and the next plan is empty. The design accepts orphan
			// registry rows as harmless; the operator's migration tooling
			// lists them. Pinned here so the day the provider or the registry
			// does reap it, this case fails and says so.
			name:            "A delete ok then TXT delete fails",
			op:              fake.OpDel,
			arm:             func(f *fake.Server) { f.Inject(fake.Fault{Op: fake.OpDel, Status: 500, Times: 1, SkipCalls: 1}) },
			before:          []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")},
			after:           nil,
			wantTXTRows:     1,
			minReconfigures: 2,
		},
		{
			name:            "reconfigure fails then empty plan",
			op:              fake.OpReconfigure,
			arm:             func(f *fake.Server) { f.Inject(fake.Fault{Op: fake.OpReconfigure, Status: 500, Times: 1}) },
			after:           []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")},
			wantTXTRows:     1,
			minReconfigures: 2,
		},
		{
			// The firewall's own failure mode from the 2026-09-15 cutover: the
			// add is acknowledged with a uuid and the row is never saved. The
			// TXT add is the first add call. The re-read after the TXT phase
			// catches it and gates the data phase, so the next reconcile finds
			// the name untaken and creates both rows. Without that gate the A
			// row would exist with no registry row, and the planner, which
			// only ever updates or deletes records it owns and never re-creates
			// a name that is taken, would leave it unowned for good.
			name: "TXT add acknowledged but not saved",
			op:   fake.OpAddHostOverride,
			arm: func(f *fake.Server) {
				f.Inject(fake.Fault{Op: fake.OpAddHostOverride, Lost: true, Times: 1})
			},
			after:           []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")},
			wantTXTRows:     1,
			minReconfigures: 2,
		},
		{
			name: "A add acknowledged but not saved",
			op:   fake.OpAddHostOverride,
			arm: func(f *fake.Server) {
				f.Inject(fake.Fault{Op: fake.OpAddHostOverride, Lost: true, Times: 1, SkipCalls: 1})
			},
			after:           []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")},
			wantTXTRows:     1,
			minReconfigures: 2,
		},
		{
			name:            "update acknowledged but not applied",
			op:              fake.OpSet,
			arm:             func(f *fake.Server) { f.Inject(fake.Fault{Op: fake.OpSet, Lost: true, Times: 1}) },
			before:          []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")},
			after:           []*endpoint.Endpoint{a(appName, 600, "192.0.2.1")},
			wantTXTRows:     1,
			minReconfigures: 2,
		},
		{
			// The A delete is the first del call. The re-read after the data
			// remove phase catches the lost delete and gates the TXT remove
			// phase, so the registry row survives to the next reconcile, which
			// still sees an owned A and removes both rows.
			name:            "A delete acknowledged but not saved",
			op:              fake.OpDel,
			arm:             func(f *fake.Server) { f.Inject(fake.Fault{Op: fake.OpDel, Lost: true, Times: 1}) },
			before:          []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")},
			after:           nil,
			wantTXTRows:     0,
			minReconfigures: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, "OPNSENSE_RETRY_ATTEMPTS=1")
			fx := seed(t, h.fake)
			h.waitForReady(readyWithin)
			reg := newRegistry(t, h.webhookURL)
			if tc.before != nil {
				converge(t, reg, tc.before, 3)
			}

			hitsBefore := h.fake.Hits(tc.op)
			tc.arm(h.fake)

			// The first reconcile after arming has to fail. That is the fault
			// firing; without it the rest of the case would be a plain
			// happy-path run wearing a fault's name.
			changed, err := reconcileOnce(t, reg, tc.after)
			if err == nil {
				t.Fatalf("armed %s fault did not fail the first reconcile (changed=%v)", tc.op, changed)
			}
			t.Logf("fault fired: %v", err)
			converge(t, reg, tc.after, 3)

			if got := h.fake.Hits(tc.op); got <= hitsBefore {
				t.Errorf("%s calls after arming = %d, want more than %d", tc.op, got, hitsBefore)
			}
			if got := h.fake.Reconfigures(); got < tc.minReconfigures {
				t.Errorf("successful reconfigures = %d, want at least %d", got, tc.minReconfigures)
			}

			// Served table: every desired target is published, the registry
			// row with it, and a deleted name is gone from it.
			for _, e := range tc.after {
				for _, target := range e.Targets {
					if !servedHas(h.fake, e.DNSName, "A", target) {
						t.Errorf("%s -> %s not served: %+v", e.DNSName, target, h.fake.Served())
					}
				}
			}
			if tc.after == nil && servedHas(h.fake, appName, "A", "192.0.2.1") {
				t.Errorf("deleted data row still served: %+v", h.fake.Served())
			}
			if served := txtServed(h.fake, appTXTName); served != (tc.wantTXTRows > 0) {
				t.Errorf("registry TXT served = %v, want %v: %+v", served, tc.wantTXTRows > 0, h.fake.Served())
			}

			// Config table: no duplicate registry rows from a retried write.
			if n := txtRows(h.fake); n != tc.wantTXTRows {
				t.Errorf("TXT rows for app = %d, want %d", n, tc.wantTXTRows)
			}
			assertUntouched(t, h.fake, fx)
		})
	}
}

func TestReconcile_RestartWithPendingReconfigure(t *testing.T) {
	h := newHarness(t, "OPNSENSE_RETRY_ATTEMPTS=1")
	fx := seed(t, h.fake)
	h.waitForReady(readyWithin)
	reg := newRegistry(t, h.webhookURL)
	h.fake.Inject(fake.Fault{Op: fake.OpReconfigure, Status: 500, Times: 1})
	if _, err := reconcileOnce(t, reg, []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")}); err == nil {
		t.Fatal("apply with a failing reconfigure did not report an error")
	}
	if servedHas(h.fake, appName, "A", "192.0.2.1") {
		t.Fatal("served despite failed reconfigure")
	}

	// The pending flag lives in memory, so a fresh process has to rediscover
	// the saved-but-unserved rows for itself. Readiness is not the signal
	// here (see waitForReady): the startup check runs in its own goroutine,
	// so wait for what it does rather than for the probe.
	h.restart()
	h.waitForReady(readyWithin)
	pollUntil(t, readyWithin, "the startup served-state check publishing the pending row", func() bool {
		return servedHas(h.fake, appName, "A", "192.0.2.1")
	})
	if !txtServed(h.fake, appTXTName) {
		t.Errorf("startup served-state check did not publish the registry TXT: %+v", h.fake.Served())
	}
	if n := txtRows(h.fake); n != 1 {
		t.Errorf("TXT rows for app = %d, want 1", n)
	}
	assertUntouched(t, h.fake, fx)
}
