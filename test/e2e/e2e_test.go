//go:build e2e

// Package e2e drives the real binary against test/fake at protocol level.
//
//	go test -tags e2e -timeout 5m ./test/e2e/...
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LukeEvansTech/external-dns-opnsense-webhook/test/fake"
)

const mediaType = "application/external.dns.webhook+json;version=1"

type harness struct {
	t          *testing.T
	fake       *fake.Server
	webhookURL string
	healthURL  string
	cmd        *exec.Cmd
	out        bytes.Buffer
}

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "external-dns-opnsense-webhook")
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd/external-dns-opnsense-webhook")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build: %v", err)
	}
	return bin
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func newHarness(t *testing.T, extraEnv ...string) *harness {
	t.Helper()
	h := &harness{t: t, fake: fake.New(t)}
	bin := buildBinary(t)
	wp, hp := freePort(t), freePort(t)
	h.webhookURL = fmt.Sprintf("http://127.0.0.1:%d", wp)
	h.healthURL = fmt.Sprintf("http://127.0.0.1:%d", hp)
	ctx, cancel := context.WithCancel(context.Background())
	h.cmd = exec.CommandContext(ctx, bin)
	h.cmd.Env = append(os.Environ(),
		"SERVER_HOST=127.0.0.1", fmt.Sprintf("SERVER_PORT=%d", wp), fmt.Sprintf("HEALTH_SERVER_ADDR=127.0.0.1:%d", hp),
		"LOG_LEVEL=debug", "LOG_FORMAT=text",
		"OPNSENSE_HOST="+h.fake.URL(), "OPNSENSE_API_KEY=k", "OPNSENSE_API_SECRET=s",
		"OPNSENSE_DOMAINS=example.com", "OPNSENSE_RETRY_INITIAL_DELAY=10ms", "OPNSENSE_RETRY_MAX_DELAY=50ms",
		"READINESS_CACHE_TTL=200ms",
	)
	h.cmd.Env = append(h.cmd.Env, extraEnv...)
	h.cmd.Stdout, h.cmd.Stderr = &h.out, &h.out
	if err := h.cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = h.cmd.Wait()
		if t.Failed() {
			t.Logf("binary output:\n%s", h.out.String())
		}
	})
	return h
}

func (h *harness) waitFor(url string, want int, within time.Duration) {
	h.t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("Accept", mediaType)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == want {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.t.Fatalf("%s did not return %d within %s", url, want, within)
}

func (h *harness) call(method, path string, body any, accept, contentType bool) (*http.Response, []byte) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, h.webhookURL+path, reader)
	if accept {
		req.Header.Set("Accept", mediaType)
	}
	if contentType {
		req.Header.Set("Content-Type", mediaType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func TestE2E_Protocol(t *testing.T) {
	h := newHarness(t)
	h.fake.AddRow(fake.Row{Hostname: "existing", Domain: "example.com", RR: "A", Server: "192.0.2.5"})
	h.fake.Reconfigure()
	h.waitFor(h.healthURL+"/readyz", 200, 10*time.Second)

	resp, raw := h.call(http.MethodGet, "/", nil, true, false)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "version=1") || !strings.Contains(string(raw), "example.com") {
		t.Fatalf("negotiate: %d %s %s", resp.StatusCode, resp.Header.Get("Content-Type"), raw)
	}

	resp, _ = h.call(http.MethodGet, "/records", nil, false, false)
	if resp.StatusCode != 406 {
		t.Errorf("records without Accept = %d, want 406", resp.StatusCode)
	}
	resp, raw = h.call(http.MethodGet, "/records", nil, true, false)
	if resp.StatusCode != 200 || !strings.Contains(string(raw), "existing.example.com") {
		t.Fatalf("records: %d %s", resp.StatusCode, raw)
	}

	changes := map[string]any{"create": []map[string]any{
		{"dnsName": "k8s.main.a-new.example.com", "recordType": "TXT", "targets": []string{`"heritage=external-dns,external-dns/owner=main"`}},
		{"dnsName": "new.example.com", "recordType": "A", "targets": []string{"192.0.2.6"}},
	}}
	resp, raw = h.call(http.MethodPost, "/records", changes, true, true)
	if resp.StatusCode != 204 {
		t.Fatalf("apply: %d %s", resp.StatusCode, raw)
	}
	if len(h.fake.Rows()) != 3 || h.fake.Reconfigures() != 2 {
		t.Errorf("rows=%d reconfigures=%d", len(h.fake.Rows()), h.fake.Reconfigures())
	}

	adjust := []map[string]any{
		{"dnsName": "Alias.example.com", "recordType": "CNAME", "targets": []string{"new.example.com"}},
		{"dnsName": "Keep.example.com", "recordType": "A", "targets": []string{"192.0.2.7"}},
	}
	resp, raw = h.call(http.MethodPost, "/adjustendpoints", adjust, true, true)
	if resp.StatusCode != 200 || strings.Contains(string(raw), "CNAME") || !strings.Contains(string(raw), "keep.example.com") {
		t.Errorf("adjust: %d %s", resp.StatusCode, raw)
	}

	big := map[string]any{"create": []map[string]any{{"dnsName": strings.Repeat("a", 6<<20), "recordType": "A"}}}
	resp, _ = h.call(http.MethodPost, "/records", big, true, true)
	if resp.StatusCode != 413 {
		t.Errorf("oversize body = %d, want 413", resp.StatusCode)
	}

	for _, u := range []string{h.webhookURL + "/healthz", h.healthURL + "/healthz"} {
		resp, err := http.Get(u)
		if err != nil {
			t.Fatalf("GET %s: %v", u, err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("%s = %d", u, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

// TestE2E_ApplyFailureReportsTheCause pins the 500 body: external-dns logs the
// response, so a failed apply has to name which phase failed rather than
// answer with a bare status line.
func TestE2E_ApplyFailureReportsTheCause(t *testing.T) {
	h := newHarness(t)
	h.waitFor(h.healthURL+"/readyz", 200, 10*time.Second)
	// Enough times to outlast the client's retry budget.
	h.fake.Inject(fake.Fault{Op: fake.OpReconfigure, Status: 500, Times: 1000})

	changes := map[string]any{"create": []map[string]any{
		{"dnsName": "doomed.example.com", "recordType": "A", "targets": []string{"192.0.2.8"}},
	}}
	resp, raw := h.call(http.MethodPost, "/records", changes, true, true)
	if resp.StatusCode != 500 {
		t.Fatalf("apply with a failing reconfigure = %d, want 500", resp.StatusCode)
	}
	if !strings.Contains(string(raw), "reconfigure") {
		t.Errorf("500 body = %q, want it to name the reconfigure failure", raw)
	}
}

func TestE2E_ReadinessFollowsUpstream(t *testing.T) {
	h := newHarness(t)
	h.waitFor(h.healthURL+"/readyz", 200, 10*time.Second)
	h.fake.Inject(fake.Fault{Op: fake.OpSearch, Status: 500, Times: 1000})
	h.waitFor(h.healthURL+"/readyz", 503, 5*time.Second)
}

func TestE2E_ListensBeforeUpstreamAnswers(t *testing.T) {
	h := newHarness(t)
	h.fake.Inject(fake.Fault{Op: fake.OpStatus, Status: 500, Times: 1000})
	h.waitFor(h.webhookURL+"/", 200, 2*time.Second)
}
