package opnsense

import (
	"context"
	"errors"
	"testing"

	"github.com/LukeEvansTech/external-dns-opnsense-webhook/test/fake"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

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

func TestApply_CreateOrdersTXTBeforeA(t *testing.T) {
	f := fake.New(t)
	p := testProvider(t, f)
	changes := &plan.Changes{Create: []*endpoint.Endpoint{
		ep("app.example.com", "A", 0, "192.0.2.1"),
		ep("k8s.main.a-app.example.com", "TXT", 0, label),
	}}
	// Phase order: the TXT add is the first add call, the A add the second.
	f.Inject(fake.Fault{Op: fake.OpAddHostOverride, Status: 500, Times: 1, SkipCalls: 1})
	err := p.ApplyChanges(context.Background(), changes)
	a, txt := rowsByKind(f)
	if err == nil || len(txt) != 1 || len(a) != 0 {
		t.Fatalf("err=%v A=%d TXT=%d; want TXT written, A failed", err, len(a), len(txt))
	}
	if f.Reconfigures() != 1 {
		t.Errorf("reconfigures = %d, want 1 after a partial write", f.Reconfigures())
	}
	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if a, txt := rowsByKind(f); len(a) != 1 || len(txt) != 1 {
		t.Errorf("after second apply: A=%d TXT=%d", len(a), len(txt))
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
	f := fake.New(t)
	id := f.AddRow(fake.Row{Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.1", Description: "external-dns"})
	f.AddAlias(id, "www", "")
	f.AddRow(fake.Row{Hostname: "k8s.main.a-app", Domain: "example.com", RR: "TXT", TXTData: stripTXTQuotes(label), Description: "external-dns"})
	p := testProvider(t, f)
	changes := &plan.Changes{
		UpdateOld: []*endpoint.Endpoint{ep("app.example.com", "A", 0, "192.0.2.1")},
		UpdateNew: []*endpoint.Endpoint{ep("app.example.com", "A", 300, "192.0.2.2")},
	}
	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatalf("apply: %v", err)
	}
	a, txt := rowsByKind(f)
	if len(a) != 1 || a[0].UUID != id || a[0].Server != "192.0.2.2" || a[0].TTL != "300" {
		t.Errorf("A row = %+v", a)
	}
	if len(txt) != 1 || len(f.Aliases()) != 1 {
		t.Errorf("TXT=%d aliases=%d; want both untouched", len(txt), len(f.Aliases()))
	}
	if f.Hits(fake.OpSet) != 1 || f.Hits(fake.OpDel) != 0 || f.Hits(fake.OpAddHostOverride) != 0 {
		t.Errorf("set=%d del=%d add=%d", f.Hits(fake.OpSet), f.Hits(fake.OpDel), f.Hits(fake.OpAddHostOverride))
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
	if a, txt := rowsByKind(f); len(a) != 1 || len(txt) != 0 {
		t.Errorf("A=%d TXT=%d", len(a), len(txt))
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
}
