package opnsense

import (
	"fmt"
	"strconv"
	"strings"

	"sigs.k8s.io/external-dns/endpoint"
)

// normaliseName lower-cases a DNS name and trims a trailing dot.
func normaliseName(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// joinName builds the FQDN the provider compares on. Lookups always compare
// joined names so hand-made rows split differently are still found.
func joinName(hostname, domain string) string {
	h, d := normaliseName(hostname), normaliseName(domain)
	if h == "" {
		return d
	}
	return h + "." + d
}

// inDomains reports whether name is a configured domain or a name under one,
// matching at a label boundary: "badexample.com" is not under "example.com".
func inDomains(name string, domains []string) bool {
	name = normaliseName(name)
	for _, d := range domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// splitName picks the longest configured domain that is a suffix of name at
// a label boundary and returns (hostname, domain). Apex names have no
// hostname and are rejected; wildcards are rejected on write in v1; names
// outside every configured domain are rejected rather than guessed.
func splitName(name string, domains []string) (string, string, error) {
	name = normaliseName(name)
	best := ""
	for _, d := range domains {
		if (name == d || strings.HasSuffix(name, "."+d)) && len(d) > len(best) {
			best = d
		}
	}
	if best == "" {
		return "", "", fmt.Errorf("%w: %q", ErrNameOutsideDomains, name)
	}
	if name == best {
		return "", "", fmt.Errorf("%w: %q", ErrApexName, name)
	}
	host := strings.TrimSuffix(name, "."+best)
	if strings.Contains(host, "*") {
		return "", "", fmt.Errorf("%w: %q", ErrWildcard, name)
	}
	return host, best, nil
}

// isWildcard reports whether a name carries a wildcard label.
//
//nolint:unused // consumed by AdjustEndpoints in a later task
func isWildcard(name string) bool { return strings.Contains(name, "*") }

// clampTTL maps an external-dns TTL onto the model's range: unset or
// negative means 0 (unset), anything above the IntegerField ceiling is
// clamped.
func clampTTL(ttl endpoint.TTL) int64 {
	switch {
	case ttl <= 0:
		return 0
	case int64(ttl) > maxTTL:
		return maxTTL
	default:
		return int64(ttl)
	}
}

// ttlField renders a TTL for the write body; the model treats "" as unset.
func ttlField(ttl int64) string {
	if ttl <= 0 {
		return ""
	}
	return strconv.FormatInt(ttl, 10)
}
