package opnsense

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LukeEvansTech/external-dns-opnsense-webhook/test/fake"
)

func testClient(t *testing.T, host string) *Client {
	t.Helper()
	cfg := validConfig()
	cfg.Host = host
	cfg.RetryInitialDelay = time.Millisecond
	cfg.RetryMaxDelay = 5 * time.Millisecond
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClient_AuthAndRoundTrip(t *testing.T) {
	var gotAuth atomic.Value
	f := fake.New(t)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		r2 := r.Clone(r.Context())
		r2.RequestURI = ""
		r2.URL.Scheme, r2.URL.Host = "http", f.URL()[len("http://"):]
		resp, err := http.DefaultTransport.RoundTrip(r2)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.WriteHeader(resp.StatusCode)
		buf := make([]byte, 1<<16)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
			}
			if rerr != nil {
				break
			}
		}
	}))
	t.Cleanup(proxy.Close)
	c := testClient(t, proxy.URL)
	ctx := context.Background()

	id, err := c.AddHostOverride(ctx, hostFields{Enabled: "1", Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.1", AddPTR: "0", Description: "external-dns"})
	if err != nil || id == "" {
		t.Fatalf("add: %v (%q)", err, id)
	}
	if a, _ := gotAuth.Load().(string); a != "Basic azpz" { // base64("k:s")
		t.Errorf("Authorization = %q", a)
	}
	page, err := c.SearchHostOverrides(ctx, 1, 10)
	if err != nil || page.Total != 1 || page.Rows[0].UUID != id {
		t.Fatalf("search: %v %+v", err, page)
	}
	row, err := c.GetHostOverride(ctx, id)
	if err != nil || row.Hostname != "app" {
		t.Fatalf("get: %v %+v", err, row)
	}
	if err := c.SetHostOverride(ctx, id, hostFields{Enabled: "1", Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.2", AddPTR: "0"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := c.Reconfigure(ctx); err != nil {
		t.Fatalf("reconfigure: %v", err)
	}
	if err := c.ServiceStatus(ctx); err != nil {
		t.Fatalf("status: %v", err)
	}
	served, err := c.ListLocalData(ctx)
	if err != nil || len(served) != 1 || served[0].Value != "192.0.2.2" {
		t.Fatalf("listlocaldata: %v %+v", err, served)
	}
	deleted, err := c.DelHostOverride(ctx, id)
	if err != nil || !deleted {
		t.Fatalf("del: %v %v", err, deleted)
	}
	deleted, err = c.DelHostOverride(ctx, id)
	if err != nil || deleted {
		t.Fatalf("second del: %v %v", err, deleted)
	}
}

func TestClient_WriteErrorCarriesValidations(t *testing.T) {
	f := fake.New(t)
	c := testClient(t, f.URL())
	_, err := c.AddHostOverride(context.Background(), hostFields{Enabled: "1", Hostname: "t", Domain: "example.com", RR: "TXT", TXTData: string(make([]byte, 300))})
	werr, ok := errors.AsType[*WriteError](err)
	if !ok || werr.Validations["host.txtdata"] == nil {
		t.Fatalf("err = %v", err)
	}
}

func TestClient_ReconfigureRequiresOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"error"}`))
	}))
	t.Cleanup(srv.Close)
	c := testClient(t, srv.URL)
	if err := c.Reconfigure(context.Background()); err == nil {
		t.Error("expected error on status != ok")
	}
}

func TestRetry_PolicyByOperation(t *testing.T) {
	cases := []struct {
		op        string
		status    int
		wantCalls int32
	}{
		{opSearchHostOverride, 500, 3},
		{opDelHostOverride, 503, 3},
		{opAddHostOverride, 500, 1},
		{opSetHostOverride, 500, 1},
		{opReconfigure, 500, 1},
		{opAddHostOverride, 429, 3},
		{opSearchHostOverride, 404, 1},
	}
	for _, tc := range cases {
		t.Run(tc.op, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				http.Error(w, "boom", tc.status)
			}))
			t.Cleanup(srv.Close)
			c := testClient(t, srv.URL)
			ctx := context.Background()
			var err error
			switch tc.op {
			case opSearchHostOverride:
				_, err = c.SearchHostOverrides(ctx, 1, 1)
			case opDelHostOverride:
				_, err = c.DelHostOverride(ctx, "x")
			case opAddHostOverride:
				_, err = c.AddHostOverride(ctx, hostFields{})
			case opSetHostOverride:
				err = c.SetHostOverride(ctx, "x", hostFields{})
			case opReconfigure:
				err = c.Reconfigure(ctx)
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if calls.Load() != tc.wantCalls {
				t.Errorf("calls = %d, want %d", calls.Load(), tc.wantCalls)
			}
		})
	}
}

func TestClient_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	c := testClient(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := c.ServiceStatus(ctx); err == nil {
		t.Error("expected context error")
	}
}
