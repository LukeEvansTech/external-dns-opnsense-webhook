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
)

func a(name string, ttl int64, targets ...string) *endpoint.Endpoint {
	return endpoint.NewEndpointWithTTL(name, endpoint.RecordTypeA, endpoint.TTL(ttl), targets...)
}

type fixtures struct {
	handRow  fake.Row
	handAlia fake.Alias
	foreign  fake.Row
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
		TXTData: "heritage=external-dns,external-dns/owner=other", Description: "external-dns",
	})
	f.AddRow(fake.Row{
		Hostname: "theirs", Domain: "example.com", RR: "A",
		Server: "192.0.2.60", Description: "external-dns",
	})
	f.Reconfigure()
	rows, aliases := f.Rows(), f.Aliases()
	return fixtures{handRow: rows[0], handAlia: aliases[0], foreign: rows[1]}
}

// untouchedProblems reports every way the protected objects differ from the
// fixtures, in both the config table and the served table. It returns the
// problems rather than failing so the known-bad control below can prove each
// branch fires.
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
	if len(f.Aliases()) != 1 || f.Aliases()[0] != fx.handAlia {
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
// untouchedProblems: an untouched table must report nothing, and each
// protected object, edited through the fake's own API, must be caught.
func TestReconcile_UntouchedControl(t *testing.T) {
	post := func(t *testing.T, f *fake.Server, path, body string) {
		t.Helper()
		resp, err := http.Post(f.URL()+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	cases := []struct {
		name   string
		mutate func(t *testing.T, f *fake.Server, fx fixtures)
	}{
		{"hand-made row edited", func(t *testing.T, f *fake.Server, fx fixtures) {
			post(t, f, "/api/unbound/settings/setHostOverride/"+fx.handRow.UUID,
				`{"host":{"hostname":"nas","domain":"example.com","rr":"A","server":"198.51.100.1"}}`)
		}},
		{"foreign TXT deleted", func(t *testing.T, f *fake.Server, fx fixtures) {
			post(t, f, "/api/unbound/settings/delHostOverride/"+fx.foreign.UUID, `{}`)
		}},
		{"hand-made alias added", func(_ *testing.T, f *fake.Server, fx fixtures) {
			f.AddAlias(fx.handRow.UUID, "extra", "")
		}},
		{"served table stale", func(t *testing.T, f *fake.Server, _ fixtures) {
			// Deleting a row nothing else asserts on, then republishing,
			// leaves the config-table checks green and only the served-table
			// check red.
			for _, r := range f.Rows() {
				if r.Hostname == "theirs" {
					post(t, f, "/api/unbound/settings/delHostOverride/"+r.UUID, `{}`)
				}
			}
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
			if got := untouchedProblems(f, fx); len(got) == 0 {
				t.Errorf("no problem reported after %s", tc.name)
			}
		})
	}
}

func TestReconcile_Lifecycle(t *testing.T) {
	h := newHarness(t)
	fx := seed(t, h.fake)
	h.waitFor(h.healthURL+"/readyz", 200, 10*time.Second)
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
		name   string
		arm    func(f *fake.Server)
		before []*endpoint.Endpoint
		after  []*endpoint.Endpoint
		// wantTXTRows is how many registry rows for appName the converged
		// table must hold. It is stated per case rather than derived from
		// after, because one fault leaves an orphan the controller cannot
		// reach (see the note on the delete case).
		wantTXTRows int
	}{
		{
			name: "txt ok then A add fails",
			arm: func(f *fake.Server) {
				f.Inject(fake.Fault{Op: fake.OpAddHostOverride, Status: 500, Times: 1, SkipCalls: 1})
			},
			after:       []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")},
			wantTXTRows: 1,
		},
		{
			name: "A add committed, response lost",
			arm: func(f *fake.Server) {
				f.Inject(fake.Fault{Op: fake.OpAddHostOverride, Status: 502, Times: 1, SkipCalls: 1, AfterCommit: true})
			},
			after:       []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")},
			wantTXTRows: 1,
		},
		{
			name:        "partial update",
			arm:         func(f *fake.Server) { f.Inject(fake.Fault{Op: fake.OpSet, Status: 500, Times: 1}) },
			before:      []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")},
			after:       []*endpoint.Endpoint{a(appName, 600, "192.0.2.1")},
			wantTXTRows: 1,
		},
		{
			// The data row goes (phase 3) and the registry row does not
			// (phase 4 fails), which is the one fault in this table that does
			// not converge to a clean table. It is not a provider defect and
			// no further reconcile can fix it: the TXT registry folds every
			// heritage-bearing TXT into its ownership map instead of
			// returning it as an endpoint, so the planner never sees a record
			// to delete and the next plan is empty. DESIGN.md records the
			// same outcome — orphan TXT rows are harmless and migrate.py
			// plan --txt-orphans lists them for review-then-delete. Pinned
			// here so the day the provider or the registry does reap it, this
			// case fails and says so.
			name:        "A delete ok then TXT delete fails",
			arm:         func(f *fake.Server) { f.Inject(fake.Fault{Op: fake.OpDel, Status: 500, Times: 3, SkipCalls: 1}) },
			before:      []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")},
			after:       nil,
			wantTXTRows: 1,
		},
		{
			name:        "reconfigure fails then empty plan",
			arm:         func(f *fake.Server) { f.Inject(fake.Fault{Op: fake.OpReconfigure, Status: 500, Times: 1}) },
			after:       []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")},
			wantTXTRows: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, "OPNSENSE_RETRY_ATTEMPTS=1")
			fx := seed(t, h.fake)
			h.waitFor(h.healthURL+"/readyz", 200, 10*time.Second)
			reg := newRegistry(t, h.webhookURL)
			if tc.before != nil {
				converge(t, reg, tc.before, 3)
			}
			tc.arm(h.fake)
			converge(t, reg, tc.after, 4)

			// Served table: every desired target is published, and a deleted
			// name is gone from it.
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
			if got := txtServed(h.fake, appTXTName); got != (tc.wantTXTRows > 0) {
				t.Errorf("registry TXT served = %v, want %v: %+v", got, tc.wantTXTRows > 0, h.fake.Served())
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
	h.waitFor(h.healthURL+"/readyz", 200, 10*time.Second)
	reg := newRegistry(t, h.webhookURL)
	h.fake.Inject(fake.Fault{Op: fake.OpReconfigure, Status: 500, Times: 1})
	_, _ = reconcileOnce(t, reg, []*endpoint.Endpoint{a(appName, 0, "192.0.2.1")})
	if servedHas(h.fake, appName, "A", "192.0.2.1") {
		t.Fatal("served despite failed reconfigure")
	}
	h.restart() // kills the binary and starts a new one on the same ports
	h.waitFor(h.healthURL+"/readyz", 200, 10*time.Second)
	deadline := time.Now().Add(10 * time.Second)
	for !servedHas(h.fake, appName, "A", "192.0.2.1") && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if !servedHas(h.fake, appName, "A", "192.0.2.1") {
		t.Fatalf("startup served-state check did not publish the row: %+v", h.fake.Served())
	}
	if !txtServed(h.fake, appTXTName) {
		t.Errorf("startup served-state check did not publish the registry TXT: %+v", h.fake.Served())
	}
	if n := txtRows(h.fake); n != 1 {
		t.Errorf("TXT rows for app = %d, want 1", n)
	}
	assertUntouched(t, h.fake, fx)
}
