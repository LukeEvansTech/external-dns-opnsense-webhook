//go:build reconcile

// Package reconcile drives external-dns v0.22.0's own webhook client, TXT
// registry and planner against the real binary and test/fake, so every layer
// between the plan and the OPNsense API is the pinned upstream code.
//
//	go test -tags reconcile -timeout 10m ./test/reconcile/...
package reconcile

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/LukeEvansTech/external-dns-opnsense-webhook/test/fake"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/pkg/apis/externaldns"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider/webhook"
	"sigs.k8s.io/external-dns/registry"
	"sigs.k8s.io/external-dns/registry/txt"
)

const mediaType = "application/external.dns.webhook+json;version=1"

// managedRecords mirrors the consuming cluster's --managed-record-types.
var managedRecords = []string{endpoint.RecordTypeA, endpoint.RecordTypeAAAA, endpoint.RecordTypeCNAME}

type harness struct {
	t          *testing.T
	fake       *fake.Server
	bin        string
	env        []string
	webhookURL string
	healthURL  string
	cmd        *exec.Cmd
	cancel     context.CancelFunc
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

// newHarness starts the fake and the binary; extraEnv overrides defaults.
func newHarness(t *testing.T, extraEnv ...string) *harness {
	t.Helper()
	h := &harness{t: t, fake: fake.New(t), bin: buildBinary(t)}
	wp, hp := freePort(t), freePort(t)
	h.webhookURL = fmt.Sprintf("http://127.0.0.1:%d", wp)
	h.healthURL = fmt.Sprintf("http://127.0.0.1:%d", hp)
	h.env = append(os.Environ(),
		"SERVER_HOST=127.0.0.1", fmt.Sprintf("SERVER_PORT=%d", wp), fmt.Sprintf("HEALTH_SERVER_ADDR=127.0.0.1:%d", hp),
		"LOG_LEVEL=debug", "LOG_FORMAT=text",
		"OPNSENSE_HOST="+h.fake.URL(), "OPNSENSE_API_KEY=k", "OPNSENSE_API_SECRET=s",
		"OPNSENSE_DOMAINS=example.com", "OPNSENSE_RETRY_INITIAL_DELAY=10ms", "OPNSENSE_RETRY_MAX_DELAY=50ms",
		"READINESS_CACHE_TTL=200ms",
	)
	h.env = append(h.env, extraEnv...)
	h.start()
	t.Cleanup(func() {
		h.stop()
		if t.Failed() {
			t.Logf("binary output:\n%s", h.out.String())
		}
	})
	return h
}

func (h *harness) start() {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.cmd = exec.CommandContext(ctx, h.bin)
	h.cmd.Env = h.env
	h.cmd.Stdout, h.cmd.Stderr = &h.out, &h.out
	if err := h.cmd.Start(); err != nil {
		cancel()
		h.t.Fatal(err)
	}
}

func (h *harness) stop() {
	if h.cancel != nil {
		h.cancel()
		_ = h.cmd.Wait()
		h.cancel = nil
	}
}

// restart kills the binary and starts a fresh process on the same ports,
// losing all in-memory state (the pending flag included).
func (h *harness) restart() {
	h.t.Helper()
	h.stop()
	h.start()
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

// newRegistry builds external-dns's real webhook client and TXT registry
// pointed at the running binary, with talos-cluster's registry settings.
func newRegistry(t *testing.T, webhookURL string) registry.Registry {
	t.Helper()
	cfg := externaldns.NewConfig()
	cfg.WebhookProviderURL = webhookURL
	cfg.WebhookProviderReadTimeout = 30 * time.Second
	cfg.WebhookProviderWriteTimeout = 180 * time.Second
	cfg.TXTOwnerID = "main"
	cfg.TXTPrefix = "k8s.main.%{record_type}-"
	cfg.ManagedDNSRecordTypes = managedRecords
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := webhook.New(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("webhook.New: %v", err)
	}
	reg, err := txt.New(cfg, p)
	if err != nil {
		t.Fatalf("txt.New: %v", err)
	}
	return reg
}

// reconcileOnce mirrors controller.RunOnce: registry records, adjust,
// plan with the sync policy, apply. It returns whether the plan had changes.
func reconcileOnce(t *testing.T, reg registry.Registry, desired []*endpoint.Endpoint) (bool, error) {
	t.Helper()
	ctx := context.Background()
	current, err := reg.Records(ctx)
	if err != nil {
		return false, err
	}
	adjusted, err := reg.AdjustEndpoints(desired)
	if err != nil {
		return false, err
	}
	pl := &plan.Plan{
		Policies:       []plan.Policy{&plan.SyncPolicy{}},
		Current:        current,
		Desired:        adjusted,
		DomainFilter:   endpoint.MatchAllDomainFilters{reg.GetDomainFilter()},
		ManagedRecords: managedRecords,
		OwnerID:        reg.OwnerID(),
	}
	pl = pl.Calculate()
	if !pl.Changes.HasChanges() {
		return false, nil
	}
	return true, reg.ApplyChanges(ctx, pl.Changes)
}

// converge runs reconciles until a no-op, failing after max attempts.
func converge(t *testing.T, reg registry.Registry, desired []*endpoint.Endpoint, max int) {
	t.Helper()
	for i := 0; i < max; i++ {
		changed, err := reconcileOnce(t, reg, desired)
		if err != nil {
			t.Logf("reconcile %d: %v (retrying)", i+1, err)
			continue
		}
		if !changed {
			return
		}
	}
	changed, err := reconcileOnce(t, reg, desired)
	if err != nil || changed {
		t.Fatalf("did not converge after %d reconciles (changed=%v err=%v)", max, changed, err)
	}
}
