package opnsense

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/LukeEvansTech/external-dns-opnsense-webhook/test/fake"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

func TestProvider_AdjustEndpoints(t *testing.T) {
	f := fake.New(t)
	p := testProvider(t, f)
	weighted := ep("weighted.example.com", "A", 0, "192.0.2.1")
	weighted.SetIdentifier = "eu-west"
	in := []*endpoint.Endpoint{
		ep("App.Example.com.", "A", 1<<40, "192.0.2.1"),
		ep("alias.example.com", "CNAME", 0, "app.example.com"),
		ep("mail.example.com", "MX", 0, "10 mx.example.com"),
		ep("*.example.com", "A", 0, "192.0.2.1"),
		ep("other.org", "A", 0, "192.0.2.1"),
		ep("example.com", "A", 0, "192.0.2.1"),
		weighted,
		ep("bad.example.com", "TXT", 0, `"has\"quote"`),
		ep("t.example.com", "TXT", 0, `"ok"`),
	}
	out, err := p.AdjustEndpoints(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("kept %d endpoints: %v", len(out), out)
	}
	if out[0].DNSName != "app.example.com" || int64(out[0].RecordTTL) != maxTTL {
		t.Errorf("first = %+v", out[0])
	}
	if out[1].DNSName != "t.example.com" || out[1].RecordType != recordTypeTXT {
		t.Errorf("second = %+v", out[1])
	}
	// The endpoint constructor already trimmed the trailing dot; the
	// lower-casing is AdjustEndpoints' own and must land on a copy.
	if in[0].DNSName != "App.Example.com" {
		t.Errorf("AdjustEndpoints mutated its input: %q", in[0].DNSName)
	}
}

// TestProvider_AdjustEndpointsReasons pins the closed set of drop reasons: a
// reason is a metric label, and an endpoint AdjustEndpoints keeps but the
// write path rejects is a plan external-dns retries forever.
func TestProvider_AdjustEndpointsReasons(t *testing.T) {
	f := fake.New(t)
	p := testProvider(t, f)
	weighted := ep("weighted.example.com", "A", 0, "192.0.2.1")
	weighted.SetIdentifier = "eu-west"
	cases := []struct {
		reason string
		e      *endpoint.Endpoint
	}{
		{"type", ep("alias.example.com", "CNAME", 0, "app.example.com")},
		{"set-identifier", weighted},
		{"wildcard", ep("*.example.com", "A", 0, "192.0.2.1")},
		{"apex", ep("example.com", "A", 0, "192.0.2.1")},
		{"domain", ep("host.other.org", "A", 0, "192.0.2.1")},
		{"txt", ep("bad.example.com", "TXT", 0, `"has\"quote"`)},
		{"", ep("good.example.com", "A", 0, "192.0.2.1")},
		{"", ep("good.example.com", "TXT", 0, `"ok"`)},
	}
	for _, tc := range cases {
		name := tc.reason
		if name == "" {
			name = "kept/" + tc.e.RecordType
		}
		t.Run(name, func(t *testing.T) {
			got := p.dropReason(tc.e, normaliseName(tc.e.DNSName))
			if got != tc.reason {
				t.Errorf("dropReason = %q, want %q", got, tc.reason)
			}
			out, err := p.AdjustEndpoints([]*endpoint.Endpoint{tc.e})
			if err != nil {
				t.Fatal(err)
			}
			if want := map[bool]int{true: 0, false: 1}[tc.reason != ""]; len(out) != want {
				t.Errorf("kept %d endpoints, want %d", len(out), want)
			}
		})
	}
}

func TestProvider_DomainFilter(t *testing.T) {
	f := fake.New(t)
	p := testProvider(t, f)
	df := p.GetDomainFilter()
	if !df.Match("x.example.com") || df.Match("x.other.org") {
		t.Error("domain filter wrong")
	}
}

// TestProvider_ApplySerialised proves the single-writer lock: an apply started
// while the lock is held makes no progress until it is released, and two
// concurrent applies both land their row.
func TestProvider_ApplySerialised(t *testing.T) {
	f := fake.New(t)
	p := testProvider(t, f)

	p.applyMu.Lock()
	blocked := make(chan error, 1)
	go func() {
		blocked <- p.ApplyChanges(context.Background(), &plan.Changes{
			Create: []*endpoint.Endpoint{ep("a.example.com", "A", 0, "192.0.2.1")},
		})
	}()
	select {
	case err := <-blocked:
		t.Fatalf("apply ran while the writer lock was held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if f.Hits(fake.OpSearch) != 0 {
		t.Errorf("apply read the table while the writer lock was held")
	}
	p.applyMu.Unlock()
	if err := <-blocked; err != nil {
		t.Fatalf("first apply: %v", err)
	}

	var wg sync.WaitGroup
	for _, name := range []string{"b", "c"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.ApplyChanges(context.Background(), &plan.Changes{
				Create: []*endpoint.Endpoint{ep(name+".example.com", "A", 0, "192.0.2.1")},
			}); err != nil {
				t.Errorf("apply %s: %v", name, err)
			}
		}()
	}
	wg.Wait()
	if len(f.Rows()) != 3 {
		t.Errorf("rows = %d, want 3", len(f.Rows()))
	}
}

func TestProvider_RecordsMapsSnapshot(t *testing.T) {
	f := fake.New(t)
	id := f.AddRow(fake.Row{Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.1", TTL: "300"})
	f.AddAlias(id, "www", "")
	f.AddRow(fake.Row{Hostname: "k8s.main.a-app", Domain: "example.com", RR: "TXT", TXTData: stripTXTQuotes(label)})
	p := testProvider(t, f)
	eps, err := p.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 3 {
		t.Fatalf("endpoints = %d: %v", len(eps), eps)
	}
	if eps[0].DNSName != "app.example.com" || eps[0].RecordType != recordTypeA || int64(eps[0].RecordTTL) != 300 {
		t.Errorf("first = %+v", eps[0])
	}
	if eps[2].DNSName != "www.example.com" || eps[2].RecordType != recordTypeA {
		t.Errorf("alias endpoint = %+v", eps[2])
	}
}

// TestProvider_ReconfigureSerialised covers invariant I5: several reads can
// notice the same pending flag, but only one of them reloads the firewall.
func TestProvider_ReconfigureSerialised(t *testing.T) {
	f := fake.New(t)
	p := testProvider(t, f)
	p.setPending(true)

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Records(context.Background()); err != nil {
				t.Errorf("Records: %v", err)
			}
		}()
	}
	wg.Wait()
	if f.Reconfigures() != 1 {
		t.Errorf("reconfigures = %d, want exactly 1", f.Reconfigures())
	}
	if p.pending.Load() {
		t.Error("pending still set after a successful repair")
	}
}
