//go:build integration

// Package integration drives the provider against a real OPNsense firewall.
//
//	OPNSENSE_HOST=https://fw OPNSENSE_API_KEY=... OPNSENSE_API_SECRET=... \
//	OPNSENSE_DOMAINS=example.com OPNSENSE_TEST_DOMAIN=example.com \
//	OPNSENSE_DIG_SERVER=192.0.2.1 go test -tags integration -timeout 15m ./test/integration/...
//
// Every name this suite writes starts with extdns-itest-; nothing else is
// ever modified or deleted. Each write reconfigures Unbound, so a run costs
// the firewall a handful of reloads.
package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LukeEvansTech/external-dns-opnsense-webhook/internal/opnsense"
	"github.com/caarlos0/env/v11"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

// prefix marks every name this suite is allowed to create or delete.
const prefix = "extdns-itest-"

// registryPrefix is the external-dns TXT registry prefix the estate uses, so
// the suite's TXT names have production's shape: <prefix><type>-<name>.
const registryPrefix = "k8s.main."

var (
	cfgOnce sync.Once
	baseCfg opnsense.Config
	cfgErr  error
)

// loadConfig parses OPNSENSE_* exactly once and hands back a copy. Config
// marks the key and secret `unset`, so env.Parse removes them from the
// environment as it reads them: parsing again in the same process would fail
// notEmpty, and every test after the first would skip while a casual reading
// of the log says the suite ran.
func loadConfig() (opnsense.Config, error) {
	cfgOnce.Do(func() { cfgErr = env.Parse(&baseCfg) })
	return baseCfg, cfgErr
}

func newProvider(t *testing.T) (*opnsense.Provider, string) {
	t.Helper()
	cfg, err := loadConfig()
	if err != nil {
		t.Skipf("OPNSENSE_* not set: %v", err)
	}
	domain := strings.ToLower(strings.TrimSuffix(os.Getenv("OPNSENSE_TEST_DOMAIN"), "."))
	if domain == "" {
		t.Skip("OPNSENSE_TEST_DOMAIN not set")
	}
	p, err := opnsense.NewProvider(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	sweep(t, p, domain)
	t.Cleanup(func() { sweep(t, p, domain) })
	return p, domain
}

// ours reports whether a record belongs to this suite: the name carries the
// test prefix, either at the front or behind a registry type label, which
// external-dns spells <registryPrefix><type>-<name>. Matching the registry
// form by the "-"+prefix infix rather than by a fixed list of type labels
// keeps AAAA and CNAME registry rows in scope for cleanup too.
func ours(name, domain string) bool {
	if !strings.HasSuffix(name, "."+domain) {
		return false
	}
	return strings.HasPrefix(name, prefix) || strings.Contains(name, "-"+prefix)
}

// sweep deletes every record with the test prefix under domain.
func sweep(t *testing.T, p *opnsense.Provider, domain string) {
	t.Helper()
	ctx := context.Background()
	records, err := p.Records(ctx)
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	var del []*endpoint.Endpoint
	for _, r := range records {
		if ours(r.DNSName, domain) {
			del = append(del, r)
		}
	}
	if len(del) == 0 {
		return
	}
	if err := p.ApplyChanges(ctx, &plan.Changes{Delete: del}); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	t.Logf("swept %d leftover records", len(del))
}

func suffix(t *testing.T) string {
	t.Helper()
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

func dig(t *testing.T, name, rrtype string) string {
	t.Helper()
	server := os.Getenv("OPNSENSE_DIG_SERVER")
	if server == "" {
		t.Skip("OPNSENSE_DIG_SERVER not set")
	}
	out, err := exec.Command("dig", "+time=3", "+tries=1", "@"+server, name, rrtype).CombinedOutput()
	if err != nil {
		t.Fatalf("dig: %v\n%s", err, out)
	}
	return string(out)
}

func TestIntegration_TXTRoundTrip(t *testing.T) {
	p, domain := newProvider(t)
	ctx := context.Background()
	name := prefix + suffix(t) + "." + domain
	txtName := registryPrefix + "a-" + name
	label := `"heritage=external-dns,external-dns/owner=itest,external-dns/resource=test/` + name + `"`
	changes := &plan.Changes{Create: []*endpoint.Endpoint{
		endpoint.NewEndpoint(name, "A", "192.0.2.1"),
		endpoint.NewEndpoint(txtName, "TXT", label),
	}}
	if err := p.ApplyChanges(ctx, changes); err != nil {
		t.Fatal(err)
	}
	records, err := p.Records(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range records {
		if r.DNSName == txtName && r.RecordType == "TXT" && r.Targets[0] == label {
			found = true
		}
	}
	if !found {
		t.Fatalf("TXT not read back as written")
	}
	out := dig(t, txtName, "TXT")
	answer := firstAnswer(out)
	t.Logf("TXT served as: %s", answer)
	if !strings.Contains(out, "NOERROR") || strings.Contains(out, `\"`) {
		t.Fatalf("dig TXT: want NOERROR with a single pair of quotes, got:\n%s", out)
	}
	// NOERROR on its own proves nothing: a name Unbound holds in a local zone
	// with no data for the type asked for answers NOERROR with an empty
	// answer section, so the value itself has to be in the answer.
	if !strings.Contains(answer, label) {
		t.Fatalf("dig TXT: the answer does not carry the written value\nwant %s\ngot  %q\n%s", label, answer, out)
	}
	if err := p.ApplyChanges(ctx, &plan.Changes{Delete: changes.Create}); err != nil {
		t.Fatal(err)
	}
	if out := dig(t, txtName, "TXT"); !strings.Contains(out, "NXDOMAIN") {
		t.Fatalf("after delete: %s", out)
	}
}

func TestIntegration_LocalDataBeatsNegativeCache(t *testing.T) {
	p, domain := newProvider(t)
	name := prefix + suffix(t) + "." + domain
	if out := dig(t, name, "A"); !strings.Contains(out, "NXDOMAIN") {
		t.Fatalf("expected NXDOMAIN before create:\n%s", out)
	}
	create := &plan.Changes{Create: []*endpoint.Endpoint{endpoint.NewEndpoint(name, "A", "192.0.2.2")}}
	if err := p.ApplyChanges(context.Background(), create); err != nil {
		t.Fatal(err)
	}
	if out := dig(t, name, "A"); !strings.Contains(out, "192.0.2.2") {
		t.Fatalf("local-data did not override the cached NXDOMAIN:\n%s", out)
	}
	_ = p.ApplyChanges(context.Background(), &plan.Changes{Delete: create.Create})
}

func TestIntegration_BatchTiming(t *testing.T) {
	p, domain := newProvider(t)
	ctx := context.Background()
	// 141 names: the migration-sized batch from the design, one A and one
	// registry TXT each.
	const names = 141
	creates := make([]*endpoint.Endpoint, 0, 2*names)
	for i := range names {
		name := fmt.Sprintf("%sbatch-%03d.%s", prefix, i, domain)
		creates = append(creates,
			endpoint.NewEndpoint(name, "A", fmt.Sprintf("192.0.2.%d", 1+i%250)),
			endpoint.NewEndpoint(registryPrefix+"a-"+name, "TXT",
				`"heritage=external-dns,external-dns/owner=itest,external-dns/resource=test/batch"`))
	}
	start := time.Now()
	if err := p.ApplyChanges(ctx, &plan.Changes{Create: creates}); err != nil {
		t.Fatal(err)
	}
	createDur := time.Since(start)
	// "saved" from the firewall is not proof the row exists: on 2026-09-15 two
	// of 282 acknowledged adds were missing from the table afterwards. Read
	// it back and require every A and every registry TXT of the batch.
	if missing := absentFrom(t, p, creates); len(missing) != 0 {
		t.Fatalf("%d of %d created rows missing after the batch create: %v", len(missing), len(creates), missing)
	}
	start = time.Now()
	if err := p.ApplyChanges(ctx, &plan.Changes{Delete: creates}); err != nil {
		t.Fatal(err)
	}
	deleteDur := time.Since(start)
	if left := len(creates) - len(absentFrom(t, p, creates)); left != 0 {
		t.Fatalf("%d of %d rows still present after the batch delete", left, len(creates))
	}
	t.Logf("batch create=%s delete=%s (%d rows each way)", createDur, deleteDur, len(creates))
	if createDur > 100*time.Second || deleteDur > 100*time.Second {
		t.Errorf("batch too slow for the 120s apply budget: create=%s delete=%s", createDur, deleteDur)
	}
}

// TestIntegration_AAAACanonicalisation records how the firewall stores an
// uncompressed IPv6 literal. If OPNsense rewrites it, the provider's target
// comparison has to normalise as well or every apply re-creates the row; the
// second apply below makes that consequence observable rather than inferred.
func TestIntegration_AAAACanonicalisation(t *testing.T) {
	p, domain := newProvider(t)
	ctx := context.Background()
	name := prefix + suffix(t) + "." + domain
	const written = "2001:db8:0:0:0:0:0:1"
	create := &plan.Changes{Create: []*endpoint.Endpoint{endpoint.NewEndpoint(name, "AAAA", written)}}
	if err := p.ApplyChanges(ctx, create); err != nil {
		t.Fatal(err)
	}
	stored := targetsFor(t, p, name, "AAAA")
	t.Logf("AAAA written=%q stored=%q", written, stored)
	if len(stored) != 1 || stored[0] != written {
		t.Logf("FINDING: OPNsense did not store the address as written; "+
			"the provider's target comparison must normalise IPv6 before it can converge (written=%q stored=%q)",
			written, stored)
	}
	// Re-apply the identical desired state: a stable provider writes nothing
	// and the row count stays at one.
	if err := p.ApplyChanges(ctx, create); err != nil {
		t.Fatal(err)
	}
	again := targetsFor(t, p, name, "AAAA")
	t.Logf("AAAA after re-apply: %q", again)
	if len(again) != 1 {
		t.Errorf("FINDING: re-applying the same AAAA left %d targets (%q); the plan never converges", len(again), again)
	}
	if err := p.ApplyChanges(ctx, &plan.Changes{Delete: create.Create}); err != nil {
		t.Fatal(err)
	}
}

// absentFrom reads the table back and returns the "<type> <name>" of every
// endpoint in eps that is not present as a record of that name and type.
func absentFrom(t *testing.T, p *opnsense.Provider, eps []*endpoint.Endpoint) []string {
	t.Helper()
	records, err := p.Records(context.Background())
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	have := make(map[string]bool, len(records))
	for _, r := range records {
		have[r.RecordType+" "+r.DNSName] = true
	}
	var missing []string
	for _, e := range eps {
		if k := e.RecordType + " " + e.DNSName; !have[k] {
			missing = append(missing, k)
		}
	}
	return missing
}

func targetsFor(t *testing.T, p *opnsense.Provider, name, rrtype string) []string {
	t.Helper()
	records, err := p.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if r.DNSName == name && r.RecordType == rrtype {
			return r.Targets
		}
	}
	t.Fatalf("%s %s not found after write", rrtype, name)
	return nil
}

func TestIntegration_WildcardReadOnly(t *testing.T) {
	p, _ := newProvider(t)
	records, err := p.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range records {
		if !strings.HasPrefix(r.DNSName, "*.") {
			continue
		}
		seen++
		zone := strings.TrimPrefix(r.DNSName, "*.")
		t.Logf("wildcard %s (%s): apex=%q child=%q missing=%q", r.DNSName, r.RecordType,
			firstAnswer(dig(t, zone, "A")),
			firstAnswer(dig(t, "explicit."+zone, "A")),
			firstAnswer(dig(t, "missing-"+suffix(t)+"."+zone, "A")))
	}
	if seen == 0 {
		t.Log("no wildcard host override exists on this firewall; nothing to observe")
	}
}

// firstAnswer returns the first record of dig's answer section, or NXDOMAIN
// or "no answer" when it has none. It keys off the section header rather than
// the field separator: dig lays the fields out in columns and only reaches for
// tabs while the owner name is short enough to fit one, falling back to a
// single space for a long name — so matching on "\tIN\t" silently misses
// exactly the long registry names this suite writes.
func firstAnswer(out string) string {
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, ";; ANSWER SECTION:") {
			continue
		}
		for _, a := range lines[i+1:] {
			a = strings.TrimSpace(a)
			switch {
			case a == "":
				return "no answer"
			case strings.HasPrefix(a, ";"):
				continue
			default:
				return a
			}
		}
	}
	if strings.Contains(out, "NXDOMAIN") {
		return "NXDOMAIN"
	}
	return "no answer"
}
