package opnsense

import (
	"context"
	"encoding/json"
	"errors"
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
