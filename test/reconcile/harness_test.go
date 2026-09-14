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

// managedRecords mirrors the consuming cluster's --managed-record-types.
var managedRecords = []string{endpoint.RecordTypeA, endpoint.RecordTypeAAAA, endpoint.RecordTypeCNAME}

// pollInterval is how often every bounded wait in this package re-checks.
const pollInterval = 50 * time.Millisecond

// binPath is the webhook binary every harness runs. Building it is a few
// seconds and the result is identical for every test, so TestMain builds it
// once for the package rather than once per test (mirroring test/e2e).
var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "reconcile-bin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating build dir: %v\n", err)
		os.Exit(1)
	}
	binPath = filepath.Join(dir, "external-dns-opnsense-webhook")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/external-dns-opnsense-webhook")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "go build: %v\n", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	// Not deferred: os.Exit below would skip it.
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type harness struct {
	t          *testing.T
	fake       *fake.Server
	env        []string
	webhookURL string
	healthURL  string
	cmd        *exec.Cmd
	cancel     context.CancelFunc
	out        bytes.Buffer
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
//
// It returns as soon as the process is spawned. Callers that need the webhook
// answering must wait for it, and should read waitForReady's contract first:
// readiness proves the OPNsense API is reachable, not that the background
// startup check has finished.
func newHarness(t *testing.T, extraEnv ...string) *harness {
	t.Helper()
	h := &harness{t: t, fake: fake.New(t)}
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
	h.cmd = exec.CommandContext(ctx, binPath)
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

// pollUntil calls cond until it reports true or within elapses, failing the
// test if it never does. Every wait in this package goes through it: the only
// sleeps here are bounded polls that re-check a condition, never a guess at
// how long something takes.
func pollUntil(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if cond() {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("%s did not happen within %s", what, within)
		}
		time.Sleep(pollInterval)
	}
}

// waitForReady blocks until /readyz answers 200.
//
// That is a narrower claim than "the webhook has finished starting up".
// Provider.Ready is a single one-row searchHostOverride, so a 200 proves only
// that the OPNsense API is reachable and the credentials are accepted. The
// startup probe — ServiceStatus followed by the served-state check that
// republishes saved-but-unserved managed rows — runs in its own goroutine from
// main and is not gated by readiness at all. A test that depends on the
// startup check must therefore wait for its effect (a row appearing in the
// served table), which is what TestReconcile_RestartWithPendingReconfigure
// does, rather than treating a ready probe as completion.
//
// No Accept header is sent: /readyz is mounted outside the webhook routes and
// does no media-type negotiation, unlike GET / and /records.
func (h *harness) waitForReady(within time.Duration) {
	h.t.Helper()
	pollUntil(h.t, within, h.healthURL+"/readyz answering 200", func() bool {
		resp, err := http.Get(h.healthURL + "/readyz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
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

// reconcileOnce mirrors controller.RunOnce: registry records, adjust, plan
// with the sync policy, apply. It returns whether the plan had changes.
//
// The domain filter is built the way RunOnce builds it,
// MatchAllDomainFilters{c.DomainFilter, registryFilter}: the controller's own
// filter first, then the one the provider negotiated on GET /. The consuming
// cluster passes its --domain-filter to the controller, so both are live
// there; here the controller half is an empty filter (match-all) and the
// registry half — OPNSENSE_DOMAINS, as the binary reported it — is the
// effective one. Keeping both makes the shape identical to the controller's
// rather than quietly testing a one-filter arrangement the cluster never runs.
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
		DomainFilter:   endpoint.MatchAllDomainFilters{endpoint.NewDomainFilter(nil), reg.GetDomainFilter()},
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
