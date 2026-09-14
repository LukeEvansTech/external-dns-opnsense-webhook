package opnsense

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/LukeEvansTech/external-dns-opnsense-webhook/internal/metrics"
	"github.com/LukeEvansTech/external-dns-opnsense-webhook/test/fake"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

// gaugeValue reads one gauge through the dto round-trip, as the metrics
// package's own tests do.
func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatalf("gauge.Write: %v", err)
	}
	return m.GetGauge().GetValue()
}

const label = `"heritage=external-dns,external-dns/owner=main,external-dns/resource=gateway-httproute/network/app"`

func testProvider(t *testing.T, f *fake.Server) *Provider {
	t.Helper()
	cfg := validConfig()
	cfg.Host = f.URL()
	cfg.RetryInitialDelay = 1e6
	cfg.RetryMaxDelay = 5e6
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p, err := NewProvider(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func ep(name, rr string, ttl int64, targets ...string) *endpoint.Endpoint {
	return endpoint.NewEndpointWithTTL(name, rr, endpoint.TTL(ttl), targets...)
}

func rowsByKind(f *fake.Server) (a, txt []fake.Row) {
	for _, r := range f.Rows() {
		if r.RR == "TXT" {
			txt = append(txt, r)
		} else {
			a = append(a, r)
		}
	}
	return a, txt
}

// dataTypes drives the A/AAAA table: the two record types the provider writes
// into a server field, which must behave identically apart from the value.
var dataTypes = []struct{ rr, first, second string }{
	{"A", "192.0.2.1", "192.0.2.2"},
	{"AAAA", "2001:db8::1", "2001:db8::2"},
}

func TestApply_CreateOrdersTXTBeforeData(t *testing.T) {
	for _, tc := range dataTypes {
		t.Run(tc.rr, func(t *testing.T) {
			f := fake.New(t)
			p := testProvider(t, f)
			changes := &plan.Changes{Create: []*endpoint.Endpoint{
				ep("app.example.com", tc.rr, 0, tc.first),
				ep("k8s.main.a-app.example.com", "TXT", 0, label),
			}}
			// Phase order: the TXT add is the first add call, the data add the second.
			f.Inject(fake.Fault{Op: fake.OpAddHostOverride, Status: 500, Times: 1, SkipCalls: 1})
			err := p.ApplyChanges(context.Background(), changes)
			a, txt := rowsByKind(f)
			if err == nil || len(txt) != 1 || len(a) != 0 {
				t.Fatalf("err=%v data=%d TXT=%d; want TXT written, data failed", err, len(a), len(txt))
			}
			if f.Reconfigures() != 1 {
				t.Errorf("reconfigures = %d, want 1 after a partial write", f.Reconfigures())
			}
			if err := p.ApplyChanges(context.Background(), changes); err != nil {
				t.Fatalf("second apply: %v", err)
			}
			a, txt = rowsByKind(f)
			if len(a) != 1 || len(txt) != 1 {
				t.Fatalf("after second apply: data=%d TXT=%d", len(a), len(txt))
			}
			if a[0].RR != tc.rr || a[0].Server != tc.first {
				t.Errorf("data row = %+v", a[0])
			}
		})
	}
}

func TestApply_DeleteOrder(t *testing.T) {
	f := fake.New(t)
	f.AddRow(fake.Row{Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.1", Description: "external-dns"})
	f.AddRow(fake.Row{Hostname: "k8s.main.a-app", Domain: "example.com", RR: "TXT", TXTData: stripTXTQuotes(label), Description: "external-dns"})
	p := testProvider(t, f)
	p.cfg.RetryAttempts = 1
	changes := &plan.Changes{Delete: []*endpoint.Endpoint{
		ep("k8s.main.a-app.example.com", "TXT", 0, label),
		ep("app.example.com", "A", 0, "192.0.2.1"),
	}}
	// Phase order guarantees the A delete is the first del call and the TXT
	// delete the second; SkipCalls makes the fault fire on the second.
	f.Inject(fake.Fault{Op: fake.OpDel, Status: 500, Times: 1, SkipCalls: 1})
	err := p.ApplyChanges(context.Background(), changes)
	a, txt := rowsByKind(f)
	if err == nil || len(a) != 0 || len(txt) != 1 {
		t.Fatalf("err=%v A=%d TXT=%d; want A gone, TXT kept, error returned", err, len(a), len(txt))
	}
	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if a, txt := rowsByKind(f); len(a) != 0 || len(txt) != 0 {
		t.Errorf("after second apply: A=%d TXT=%d", len(a), len(txt))
	}
}

func TestApply_UpdateInPlaceKeepsUUIDAndChildren(t *testing.T) {
	for _, tc := range dataTypes {
		t.Run(tc.rr, func(t *testing.T) {
			f := fake.New(t)
			id := f.AddRow(fake.Row{Hostname: "app", Domain: "example.com", RR: tc.rr, Server: tc.first, Description: "external-dns"})
			f.AddAlias(id, "www", "")
			f.AddRow(fake.Row{Hostname: "k8s.main.a-app", Domain: "example.com", RR: "TXT", TXTData: stripTXTQuotes(label), Description: "external-dns"})
			p := testProvider(t, f)
			changes := &plan.Changes{
				UpdateOld: []*endpoint.Endpoint{ep("app.example.com", tc.rr, 0, tc.first)},
				UpdateNew: []*endpoint.Endpoint{ep("app.example.com", tc.rr, 300, tc.second)},
			}
			if err := p.ApplyChanges(context.Background(), changes); err != nil {
				t.Fatalf("apply: %v", err)
			}
			a, txt := rowsByKind(f)
			if len(a) != 1 || a[0].UUID != id || a[0].Server != tc.second || a[0].TTL != "300" {
				t.Errorf("data row = %+v", a)
			}
			if len(txt) != 1 || len(f.Aliases()) != 1 {
				t.Errorf("TXT=%d aliases=%d; want both untouched", len(txt), len(f.Aliases()))
			}
			if f.Hits(fake.OpSet) != 1 || f.Hits(fake.OpDel) != 0 || f.Hits(fake.OpAddHostOverride) != 0 {
				t.Errorf("set=%d del=%d add=%d", f.Hits(fake.OpSet), f.Hits(fake.OpDel), f.Hits(fake.OpAddHostOverride))
			}
		})
	}
}

func TestApply_MultiTargetConverges(t *testing.T) {
	f := fake.New(t)
	id1 := f.AddRow(fake.Row{Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.1", Description: "external-dns"})
	p := testProvider(t, f)
	if err := p.ApplyChanges(context.Background(), &plan.Changes{
		UpdateOld: []*endpoint.Endpoint{ep("app.example.com", "A", 0, "192.0.2.1")},
		UpdateNew: []*endpoint.Endpoint{ep("app.example.com", "A", 0, "192.0.2.1", "192.0.2.2")},
	}); err != nil {
		t.Fatal(err)
	}
	if a, _ := rowsByKind(f); len(a) != 2 {
		t.Fatalf("rows = %d, want 2", len(a))
	}
	if err := p.ApplyChanges(context.Background(), &plan.Changes{
		UpdateOld: []*endpoint.Endpoint{ep("app.example.com", "A", 0, "192.0.2.1", "192.0.2.2")},
		UpdateNew: []*endpoint.Endpoint{ep("app.example.com", "A", 0, "192.0.2.2")},
	}); err != nil {
		t.Fatal(err)
	}
	a, _ := rowsByKind(f)
	if len(a) != 1 || a[0].Server != "192.0.2.2" || a[0].UUID == id1 {
		t.Errorf("rows = %+v", a)
	}
}

func TestApply_DeleteBlockedByAliasChildren(t *testing.T) {
	f := fake.New(t)
	id := f.AddRow(fake.Row{Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.1", Description: "external-dns"})
	f.AddAlias(id, "www", "")
	p := testProvider(t, f)
	err := p.ApplyChanges(context.Background(), &plan.Changes{Delete: []*endpoint.Endpoint{ep("app.example.com", "A", 0, "192.0.2.1")}})
	if !errors.Is(err, ErrAliasChildren) {
		t.Fatalf("err = %v, want ErrAliasChildren", err)
	}
	if len(f.Rows()) != 1 || len(f.Aliases()) != 1 || f.Hits(fake.OpDel) != 0 {
		t.Error("row or alias was touched")
	}
}

func TestApply_IdempotentAndLostResponse(t *testing.T) {
	f := fake.New(t)
	p := testProvider(t, f)
	create := &plan.Changes{Create: []*endpoint.Endpoint{ep("app.example.com", "A", 0, "192.0.2.1")}}
	f.Inject(fake.Fault{Op: fake.OpAddHostOverride, Status: 502, Times: 1, AfterCommit: true})
	if err := p.ApplyChanges(context.Background(), create); err == nil {
		t.Fatal("expected the lost-response add to surface as an error")
	}
	if len(f.Rows()) != 1 {
		t.Fatalf("rows = %d after lost response", len(f.Rows()))
	}
	if err := p.ApplyChanges(context.Background(), create); err != nil {
		t.Fatal(err)
	}
	if err := p.ApplyChanges(context.Background(), create); err != nil {
		t.Fatal(err)
	}
	if len(f.Rows()) != 1 {
		t.Errorf("rows = %d, want 1 (idempotent)", len(f.Rows()))
	}
}

func TestApply_PendingReconfigureRepairedByRecords(t *testing.T) {
	f := fake.New(t)
	p := testProvider(t, f)
	p.cfg.RetryAttempts = 1
	f.Inject(fake.Fault{Op: fake.OpReconfigure, Status: 500, Times: 1})
	err := p.ApplyChanges(context.Background(), &plan.Changes{Create: []*endpoint.Endpoint{ep("app.example.com", "A", 0, "192.0.2.1")}})
	if err == nil || !p.pending.Load() {
		t.Fatalf("err=%v pending=%v", err, p.pending.Load())
	}
	if len(f.Served()) != 0 {
		t.Fatal("served before a successful reconfigure")
	}
	if _, err := p.Records(context.Background()); err != nil {
		t.Fatalf("Records: %v", err)
	}
	if p.pending.Load() || len(f.Served()) != 1 {
		t.Errorf("pending=%v served=%d", p.pending.Load(), len(f.Served()))
	}
}

func TestApply_NoWritesNoReconfigure(t *testing.T) {
	f := fake.New(t)
	f.AddRow(fake.Row{Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.1", Description: "external-dns", AddPTR: "0"})
	p := testProvider(t, f)
	if err := p.ApplyChanges(context.Background(), &plan.Changes{Create: []*endpoint.Endpoint{ep("app.example.com", "A", 0, "192.0.2.1")}}); err != nil {
		t.Fatal(err)
	}
	if f.Reconfigures() != 0 {
		t.Errorf("reconfigures = %d, want 0 when nothing changed", f.Reconfigures())
	}
}

// TestApply_InvalidTXTFailsThatEndpointOnly holds invariant I1 for a registry
// TXT the fold rejected rather than one whose write failed. The row is equally
// absent either way, so the A row it would have claimed is not created on this
// cycle; nothing is written at all, so no reconfigure follows; and the next
// plan carrying a valid TXT converges both rows.
func TestApply_InvalidTXTFailsThatEndpointOnly(t *testing.T) {
	f := fake.New(t)
	p := testProvider(t, f)
	err := p.ApplyChanges(context.Background(), &plan.Changes{Create: []*endpoint.Endpoint{
		ep("app.example.com", "A", 0, "192.0.2.1"),
		ep("k8s.main.a-app.example.com", "TXT", 0, `"bad\"quote"`),
	}})
	if !errors.Is(err, ErrTXTInvalid) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "TXT k8s.main.a-app.example.com") {
		t.Errorf("err = %v; want the rejected TXT named", err)
	}
	if a, txt := rowsByKind(f); len(a) != 0 || len(txt) != 0 {
		t.Errorf("A=%d TXT=%d; want the data create gated on the rejected TXT", len(a), len(txt))
	}
	if f.Hits(fake.OpAddHostOverride) != 0 {
		t.Errorf("add calls = %d, want 0: the data phase must not have run", f.Hits(fake.OpAddHostOverride))
	}
	// Nothing reached the firewall, so there is no saved-versus-served gap to
	// close and the reload is not owed.
	if f.Reconfigures() != 0 {
		t.Errorf("reconfigures = %d, want 0 when nothing was written", f.Reconfigures())
	}
	if err := p.ApplyChanges(context.Background(), &plan.Changes{Create: []*endpoint.Endpoint{
		ep("app.example.com", "A", 0, "192.0.2.1"),
		ep("k8s.main.a-app.example.com", "TXT", 0, label),
	}}); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if a, txt := rowsByKind(f); len(a) != 1 || len(txt) != 1 {
		t.Errorf("after second apply: A=%d TXT=%d; want both converged", len(a), len(txt))
	}
}

// TestApply_FailedConvergeKeepsExistingRows holds invariant I2's second half:
// when the desired targets could not all be written, the rows they were meant
// to replace stay, so the name never resolves to nothing.
func TestApply_FailedConvergeKeepsExistingRows(t *testing.T) {
	f := fake.New(t)
	f.AddRow(fake.Row{Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.1", Description: "external-dns"})
	p := testProvider(t, f)
	f.Inject(fake.Fault{Op: fake.OpSet, Status: 500, Times: 1})
	err := p.ApplyChanges(context.Background(), &plan.Changes{
		UpdateOld: []*endpoint.Endpoint{ep("app.example.com", "A", 0, "192.0.2.1")},
		UpdateNew: []*endpoint.Endpoint{ep("app.example.com", "A", 0, "192.0.2.2")},
	})
	if err == nil {
		t.Fatal("expected the failed write to surface as an error")
	}
	if f.Hits(fake.OpDel) != 0 {
		t.Errorf("del=%d; a failed converge must not remove rows", f.Hits(fake.OpDel))
	}
	a, _ := rowsByKind(f)
	if len(a) != 1 || a[0].Server != "192.0.2.1" {
		t.Errorf("rows = %+v; the name lost its only data row after a failed write", a)
	}
}

// TestApply_TXTCreateFailureBlocksDataCreate holds the protective half of
// invariant I1: if the registry TXT could not be written, the data rows it
// would have claimed are not created either, or they would be left with
// nothing recording who owns them.
func TestApply_TXTCreateFailureBlocksDataCreate(t *testing.T) {
	f := fake.New(t)
	p := testProvider(t, f)
	changes := &plan.Changes{Create: []*endpoint.Endpoint{
		ep("app.example.com", "A", 0, "192.0.2.1"),
		ep("k8s.main.a-app.example.com", "TXT", 0, label),
	}}
	// No SkipCalls: the fault lands on the TXT add, which is the first one.
	f.Inject(fake.Fault{Op: fake.OpAddHostOverride, Status: 500, Times: 1})
	err := p.ApplyChanges(context.Background(), changes)
	a, txt := rowsByKind(f)
	if err == nil || len(txt) != 0 || len(a) != 0 {
		t.Fatalf("err=%v A=%d TXT=%d; want neither row written", err, len(a), len(txt))
	}
	if f.Hits(fake.OpAddHostOverride) != 1 {
		t.Errorf("add calls = %d, want 1: the data phase must not have run", f.Hits(fake.OpAddHostOverride))
	}
	// The attempt itself is what forces the reload: an add whose response was
	// lost may still have committed, so pending is set before the call and a
	// reconfigure has to follow whether or not the call came back.
	if f.Reconfigures() != 1 {
		t.Errorf("reconfigures = %d, want 1 after an attempted write", f.Reconfigures())
	}
	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if a, txt := rowsByKind(f); len(a) != 1 || len(txt) != 1 {
		t.Errorf("after second apply: A=%d TXT=%d; want both converged", len(a), len(txt))
	}
}

// TestApply_DataDeleteFailureKeepsTXT is the mirror: if a data row could not
// be removed, its registry TXT stays too, so the row is never left orphaned.
func TestApply_DataDeleteFailureKeepsTXT(t *testing.T) {
	f := fake.New(t)
	f.AddRow(fake.Row{Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.1", Description: "external-dns"})
	f.AddRow(fake.Row{Hostname: "k8s.main.a-app", Domain: "example.com", RR: "TXT", TXTData: stripTXTQuotes(label), Description: "external-dns"})
	p := testProvider(t, f)
	// Deletes are idempotent and therefore retried; one attempt keeps the
	// fault pointed at the single call the test is about.
	p.cfg.RetryAttempts = 1
	changes := &plan.Changes{Delete: []*endpoint.Endpoint{
		ep("k8s.main.a-app.example.com", "TXT", 0, label),
		ep("app.example.com", "A", 0, "192.0.2.1"),
	}}
	// No SkipCalls: the fault lands on the A delete, which is the first one.
	f.Inject(fake.Fault{Op: fake.OpDel, Status: 500, Times: 1})
	err := p.ApplyChanges(context.Background(), changes)
	a, txt := rowsByKind(f)
	if err == nil || len(a) != 1 || len(txt) != 1 {
		t.Fatalf("err=%v A=%d TXT=%d; want both rows kept", err, len(a), len(txt))
	}
	if f.Hits(fake.OpDel) != 1 {
		t.Errorf("del calls = %d, want 1: the TXT phase must not have run", f.Hits(fake.OpDel))
	}
	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if a, txt := rowsByKind(f); len(a) != 0 || len(txt) != 0 {
		t.Errorf("after second apply: A=%d TXT=%d; want both removed", len(a), len(txt))
	}
}

// TestApply_PendingRepairedByEmptyApply covers the other half of invariant I4:
// an apply that writes nothing still reloads the firewall when an earlier
// reconfigure failed, so saved and served do not stay apart until the next read.
func TestApply_PendingRepairedByEmptyApply(t *testing.T) {
	f := fake.New(t)
	p := testProvider(t, f)
	p.cfg.RetryAttempts = 1
	create := &plan.Changes{Create: []*endpoint.Endpoint{ep("app.example.com", "A", 0, "192.0.2.1")}}
	f.Inject(fake.Fault{Op: fake.OpReconfigure, Status: 500, Times: 1})
	if err := p.ApplyChanges(context.Background(), create); err == nil || !p.pending.Load() {
		t.Fatalf("setup: the reconfigure fault did not leave the apply pending")
	}
	if f.Reconfigures() != 0 || len(f.Served()) != 0 {
		t.Fatalf("reconfigures=%d served=%d; want nothing published yet", f.Reconfigures(), len(f.Served()))
	}
	// The row now exists, so this apply writes nothing at all.
	if err := p.ApplyChanges(context.Background(), create); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if f.Hits(fake.OpSet) != 0 || f.Hits(fake.OpAddHostOverride) != 1 || f.Hits(fake.OpDel) != 0 {
		t.Errorf("second apply wrote: set=%d add=%d del=%d", f.Hits(fake.OpSet), f.Hits(fake.OpAddHostOverride), f.Hits(fake.OpDel))
	}
	if p.pending.Load() || f.Reconfigures() != 1 || len(f.Served()) != 1 {
		t.Errorf("pending=%v reconfigures=%d served=%d", p.pending.Load(), f.Reconfigures(), len(f.Served()))
	}
	// The flag and the gauge an operator alerts on must agree.
	if got := gaugeValue(t, metrics.Get().PendingReconfigure.WithLabelValues(metrics.ProviderName)); got != 0 {
		t.Errorf("opnsense_pending_reconfigure = %v, want 0", got)
	}
}

// TestApply_TXTFailureKeepsExistingDataRows is the removal half of the phase
// gate: skipping the data add/set phase must not leave the data remove phase
// treating rows as surplus, or a failed TXT write would take the live data
// rows with it.
func TestApply_TXTFailureKeepsExistingDataRows(t *testing.T) {
	f := fake.New(t)
	f.AddRow(fake.Row{Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.1", Description: "external-dns"})
	p := testProvider(t, f)
	changes := &plan.Changes{
		Create:    []*endpoint.Endpoint{ep("k8s.main.a-app.example.com", "TXT", 0, label)},
		UpdateOld: []*endpoint.Endpoint{ep("app.example.com", "A", 0, "192.0.2.1")},
		UpdateNew: []*endpoint.Endpoint{ep("app.example.com", "A", 0, "192.0.2.2")},
	}
	// The TXT add is the first add call; its failure gates the data phase out.
	f.Inject(fake.Fault{Op: fake.OpAddHostOverride, Status: 500, Times: 1})
	err := p.ApplyChanges(context.Background(), changes)
	if err == nil {
		t.Fatal("expected the failed TXT create to surface as an error")
	}
	if f.Hits(fake.OpDel) != 0 {
		t.Errorf("del=%d; the gated-out phase's rows must not be removed", f.Hits(fake.OpDel))
	}
	a, txt := rowsByKind(f)
	if len(a) != 1 || a[0].Server != "192.0.2.1" || len(txt) != 0 {
		t.Fatalf("data=%+v TXT=%d; want the live row untouched", a, len(txt))
	}
	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	a, txt = rowsByKind(f)
	if len(a) != 1 || a[0].Server != "192.0.2.2" || len(txt) != 1 {
		t.Errorf("after second apply: data=%+v TXT=%d", a, len(txt))
	}
}

func TestApply_RejectsUnwritablePlans(t *testing.T) {
	cases := []struct {
		name    string
		changes *plan.Changes
		want    string
	}{
		{
			// A create with nothing to point at cannot become a row, and an
			// empty desired set would read as "delete everything at this name".
			name:    "zeroTargetCreate",
			changes: &plan.Changes{Create: []*endpoint.Endpoint{ep("app.example.com", "A", 0)}},
			want:    "no targets",
		},
		{
			name: "conflictingCreates",
			changes: &plan.Changes{Create: []*endpoint.Endpoint{
				ep("app.example.com", "A", 0, "192.0.2.1"),
				ep("app.example.com", "A", 0, "192.0.2.9"),
			}},
			want: "two ways",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fake.New(t)
			p := testProvider(t, f)
			err := p.ApplyChanges(context.Background(), tc.changes)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.want)
			}
			if len(f.Rows()) != 0 || f.Reconfigures() != 0 {
				t.Errorf("rows=%d reconfigures=%d; want nothing written", len(f.Rows()), f.Reconfigures())
			}
		})
	}
}

// TestApply_TXTOnlyPlan exercises the phases the other tests always populate:
// with no data keys, phases 2 and 3 select nothing and must still leave the
// TXT phases free to run.
func TestApply_TXTOnlyPlan(t *testing.T) {
	f := fake.New(t)
	p := testProvider(t, f)
	create := &plan.Changes{Create: []*endpoint.Endpoint{ep("k8s.main.a-app.example.com", "TXT", 0, label)}}
	if err := p.ApplyChanges(context.Background(), create); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, txt := rowsByKind(f); len(txt) != 1 {
		t.Fatalf("TXT rows = %d after create", len(txt))
	}
	del := &plan.Changes{Delete: []*endpoint.Endpoint{ep("k8s.main.a-app.example.com", "TXT", 0, label)}}
	if err := p.ApplyChanges(context.Background(), del); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(f.Rows()) != 0 {
		t.Errorf("rows = %d after delete, want 0", len(f.Rows()))
	}
	if f.Reconfigures() != 2 {
		t.Errorf("reconfigures = %d, want 2", f.Reconfigures())
	}
}

// TestApply_WorkersOneAndFourConverge runs the same plan serially and with the
// default fan-out. The end state and the call counts must not depend on the
// worker count; run under -race, it is also what exercises the shared snapshot
// index from several goroutines at once.
func TestApply_WorkersOneAndFourConverge(t *testing.T) {
	const keys = 6
	fingerprint := func(f *fake.Server) []string {
		out := make([]string, 0, len(f.Rows()))
		for _, r := range f.Rows() {
			out = append(out, fmt.Sprintf("%s|%s.%s|%s|%s|%s|%s|%s",
				r.RR, r.Hostname, r.Domain, r.Server, r.TXTData, r.TTL, r.AddPTR, r.Description))
		}
		sort.Strings(out)
		return out
	}
	counts := func(f *fake.Server) map[string]int {
		return map[string]int{
			"add":         f.Hits(fake.OpAddHostOverride),
			"set":         f.Hits(fake.OpSet),
			"del":         f.Hits(fake.OpDel),
			"search":      f.Hits(fake.OpSearch),
			"reconfigure": f.Reconfigures(),
		}
	}
	build := func(del bool) *plan.Changes {
		eps := make([]*endpoint.Endpoint, 0, 2*keys)
		for i := range keys {
			eps = append(eps,
				ep(fmt.Sprintf("app%d.example.com", i), "A", 300, fmt.Sprintf("192.0.2.%d", i+1)),
				ep(fmt.Sprintf("k8s.main.a-app%d.example.com", i), "TXT", 0, fmt.Sprintf(`"owner=main,n=%d"`, i)))
		}
		if del {
			return &plan.Changes{Delete: eps}
		}
		return &plan.Changes{Create: eps}
	}

	type outcome struct {
		rows  []string
		hits  map[string]int
		final int
	}
	run := func(t *testing.T, workers int) outcome {
		t.Helper()
		f := fake.New(t)
		p := testProvider(t, f)
		p.cfg.ApplyWorkers = workers
		if err := p.ApplyChanges(context.Background(), build(false)); err != nil {
			t.Fatalf("create with %d workers: %v", workers, err)
		}
		if len(f.Rows()) != 2*keys {
			t.Fatalf("rows = %d with %d workers, want %d", len(f.Rows()), workers, 2*keys)
		}
		got := outcome{rows: fingerprint(f)}
		if err := p.ApplyChanges(context.Background(), build(true)); err != nil {
			t.Fatalf("delete with %d workers: %v", workers, err)
		}
		got.hits, got.final = counts(f), len(f.Rows())
		return got
	}

	one, four := run(t, 1), run(t, 4)
	if strings.Join(one.rows, "\n") != strings.Join(four.rows, "\n") {
		t.Errorf("rows differ by worker count:\n1: %v\n4: %v", one.rows, four.rows)
	}
	if fmt.Sprint(one.hits) != fmt.Sprint(four.hits) {
		t.Errorf("call counts differ by worker count: 1=%v 4=%v", one.hits, four.hits)
	}
	if one.final != 0 || four.final != 0 {
		t.Errorf("rows left after delete: 1=%d 4=%d", one.final, four.final)
	}
}
