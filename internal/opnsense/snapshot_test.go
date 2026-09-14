package opnsense

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/LukeEvansTech/external-dns-opnsense-webhook/test/fake"
)

func TestSnapshot_PaginatesAndMaps(t *testing.T) {
	f := fake.New(t)
	app := f.AddRow(fake.Row{Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.1", TTL: "600"})
	f.AddRow(fake.Row{Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.2", TTL: "300"})
	f.AddRow(fake.Row{Hostname: "k8s.main.a-app", Domain: "example.com", RR: "TXT", TXTData: "heritage=external-dns,external-dns/owner=main"})
	f.AddRow(fake.Row{Hostname: "old", Domain: "example.com", RR: "A", Server: "192.0.2.9", Enabled: "0"})
	f.AddRow(fake.Row{Hostname: "mail", Domain: "example.com", RR: "MX", MX: "mx.example.com", MXPrio: "10"})
	f.AddAlias(app, "www", "")

	c := testClient(t, f.URL())
	c.cfg.PageSize = 2
	snap, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Total != 5 || f.Hits(fake.OpSearch) != 3 {
		t.Errorf("total=%d searches=%d", snap.Total, f.Hits(fake.OpSearch))
	}

	eps := snap.Endpoints()
	got := map[string]string{}
	for _, ep := range eps {
		targets := append([]string(nil), ep.Targets...)
		sort.Strings(targets)
		got[ep.DNSName+"/"+ep.RecordType] = strings.Join(targets, ",") + " ttl=" + itoa(int64(ep.RecordTTL))
	}
	want := map[string]string{
		"app.example.com/A":              "192.0.2.1,192.0.2.2 ttl=300",
		"www.example.com/A":              "192.0.2.1 ttl=600",
		"k8s.main.a-app.example.com/TXT": `"heritage=external-dns,external-dns/owner=main" ttl=0`,
		"mail.example.com/MX":            "10 mx.example.com ttl=0",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["old.example.com/A"]; ok {
		t.Error("disabled row leaked into endpoints")
	}
	if len(got) != len(want) {
		t.Errorf("endpoints = %v", got)
	}
}

// pagesServer answers searchHostOverride calls from a flat script, one page
// per call in order, so a test can express "first read inconsistent, second
// read fine" as a sequence of pages. Past the end it answers an empty page
// carrying the last scripted total, like OPNsense past the last page.
func pagesServer(t *testing.T, script []searchPage) *httptest.Server {
	t.Helper()
	var call atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		i := int(call.Add(1)) - 1
		if i < len(script) {
			_ = json.NewEncoder(w).Encode(script[i])
			return
		}
		_ = json.NewEncoder(w).Encode(searchPage{Total: script[len(script)-1].Total, Current: i + 1})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func row(id, host string) hostRow {
	return hostRow{UUID: id, Enabled: "1", Hostname: host, Domain: "example.com", RR: "A", Server: "192.0.2.1"}
}

func TestSnapshot_DuplicateOnBoundaryTolerated(t *testing.T) {
	srv := pagesServer(t, []searchPage{
		{Rows: []hostRow{row("1", "a"), row("2", "b")}, Total: 3, Current: 1},
		{Rows: []hostRow{row("2", "b"), row("3", "c")}, Total: 3, Current: 2},
	})
	c := testClient(t, srv.URL)
	c.cfg.PageSize = 2
	snap, err := c.Snapshot(context.Background())
	if err != nil || len(snap.rows) != 3 {
		t.Fatalf("err=%v rows=%d", err, len(snap.rows))
	}
}

func TestSnapshot_ChangingTotalRestarts(t *testing.T) {
	srv := pagesServer(t, []searchPage{
		{Rows: []hostRow{row("1", "a"), row("2", "b")}, Total: 3, Current: 1}, // read 1, page 1
		{Rows: []hostRow{row("3", "c")}, Total: 2, Current: 2},                // read 1, page 2: total moved
		{Rows: []hostRow{row("1", "a"), row("2", "b")}, Total: 2, Current: 1}, // read 2: consistent
	})
	c := testClient(t, srv.URL)
	c.cfg.PageSize = 2
	snap, err := c.Snapshot(context.Background())
	if err != nil || len(snap.rows) != 2 {
		t.Fatalf("err=%v rows=%d", err, len(snap.rows))
	}
}

func TestSnapshot_VanishedRowFailsAfterAttempts(t *testing.T) {
	short := []searchPage{
		{Rows: []hostRow{row("1", "a"), row("2", "b")}, Total: 3, Current: 1},
		{Rows: nil, Total: 3, Current: 2},
	}
	srv := pagesServer(t, append(append(append([]searchPage{}, short...), short...), short...))
	c := testClient(t, srv.URL)
	c.cfg.PageSize = 2
	c.cfg.ReadAttempts = 3
	_, err := c.Snapshot(context.Background())
	if !errors.Is(err, ErrInconsistentRead) {
		t.Fatalf("err = %v, want ErrInconsistentRead", err)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestSnapshot_EmptyTable(t *testing.T) {
	srv := pagesServer(t, []searchPage{{Total: 0, Current: 1}})
	c := testClient(t, srv.URL)
	c.cfg.PageSize = 2
	snap, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Total != 0 || len(snap.rows) != 0 {
		t.Fatalf("total=%d rows=%d", snap.Total, len(snap.rows))
	}
	if eps := snap.Endpoints(); len(eps) != 0 {
		t.Errorf("Endpoints = %v, want empty", eps)
	}
}

func TestSnapshot_EndpointsOrderStable(t *testing.T) {
	f := fake.New(t)
	f.AddRow(fake.Row{Hostname: "b", Domain: "example.com", RR: "A", Server: "192.0.2.2"})
	f.AddRow(fake.Row{Hostname: "a", Domain: "example.com", RR: "A", Server: "192.0.2.3"})
	f.AddRow(fake.Row{Hostname: "a", Domain: "example.com", RR: "A", Server: "192.0.2.1"})
	f.AddRow(fake.Row{Hostname: "a", Domain: "example.com", RR: "TXT", TXTData: "v=spf1 ~all"})

	c := testClient(t, f.URL())
	snap, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	first := snap.Endpoints()
	second := snap.Endpoints()
	if len(first) != len(second) {
		t.Fatalf("length differs: %d vs %d", len(first), len(second))
	}
	for i := range first {
		a, b := first[i], second[i]
		if a.DNSName != b.DNSName || a.RecordType != b.RecordType || strings.Join(a.Targets, ",") != strings.Join(b.Targets, ",") {
			t.Errorf("order mismatch at %d: %+v vs %+v", i, a, b)
		}
	}
}

func TestSnapshot_MixedTTLWarnsOnce(t *testing.T) {
	cases := []struct {
		name     string
		ttls     []string
		wantTTL  int64
		wantWarn bool
	}{
		{"mixedUnsetAndExplicit", []string{"", "600"}, 600, true},
		{"matchingExplicit", []string{"300", "300"}, 300, false},
		{"unsetOnly", []string{"", ""}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fake.New(t)
			for i, ttl := range tc.ttls {
				server := "192.0.2." + itoa(int64(i+1))
				f.AddRow(fake.Row{Hostname: "app", Domain: "example.com", RR: "A", Server: server, TTL: ttl})
			}
			c := testClient(t, f.URL())
			snap, err := c.Snapshot(context.Background())
			if err != nil {
				t.Fatalf("Snapshot: %v", err)
			}

			prev := slog.Default()
			var buf bytes.Buffer
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
			defer slog.SetDefault(prev)

			eps := snap.Endpoints()
			if len(eps) != 1 || int64(eps[0].RecordTTL) != tc.wantTTL {
				t.Fatalf("eps = %+v, want one endpoint with ttl %d", eps, tc.wantTTL)
			}

			const marker = "grouped rows have different TTLs"
			count := strings.Count(buf.String(), marker)
			switch {
			case tc.wantWarn && count != 1:
				t.Errorf("warning count = %d, want exactly 1 (log: %q)", count, buf.String())
			case !tc.wantWarn && count != 0:
				t.Errorf("unexpected warning (log: %q)", buf.String())
			}
		})
	}
}

func TestSnapshot_AliasOnTXTParent(t *testing.T) {
	f := fake.New(t)
	txt := f.AddRow(fake.Row{Hostname: "k8s.main.a-app", Domain: "example.com", RR: "TXT", TXTData: "heritage=external-dns"})
	f.AddAlias(txt, "txtalias", "")

	c := testClient(t, f.URL())
	snap, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	for _, ep := range snap.Endpoints() {
		if ep.DNSName != "txtalias.example.com" {
			continue
		}
		if ep.RecordType != "TXT" || len(ep.Targets) != 1 || ep.Targets[0] != `"heritage=external-dns"` {
			t.Fatalf("alias endpoint = %+v", ep)
		}
		return
	}
	t.Fatalf("no TXT endpoint for txtalias.example.com in %v", snap.Endpoints())
}

func TestSnapshot_DuplicateRowsYieldOneTarget(t *testing.T) {
	f := fake.New(t)
	for range 2 {
		f.AddRow(fake.Row{Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.1", TTL: "300"})
	}
	c := testClient(t, f.URL())
	snap, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	eps := snap.Endpoints()
	if len(eps) != 1 {
		t.Fatalf("eps = %+v, want one endpoint", eps)
	}
	if len(eps[0].Targets) != 1 || eps[0].Targets[0] != "192.0.2.1" {
		t.Errorf("targets = %v, want the duplicate folded away", eps[0].Targets)
	}
	if int64(eps[0].RecordTTL) != 300 {
		t.Errorf("ttl = %d, want 300", eps[0].RecordTTL)
	}
	if snap.Total != 2 {
		t.Errorf("Total = %d; the duplicate row still exists on the firewall", snap.Total)
	}
}
