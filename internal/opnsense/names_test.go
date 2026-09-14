package opnsense

import (
	"errors"
	"testing"

	"sigs.k8s.io/external-dns/endpoint"
)

func TestNames_Join(t *testing.T) {
	if got := joinName("App", "Example.com."); got != "app.example.com" {
		t.Errorf("join = %q", got)
	}
	if got := joinName("", "example.com"); got != "example.com" {
		t.Errorf("join empty host = %q", got)
	}
	if got := joinName("..", "example.com"); got != "example.com" {
		t.Errorf("join dots-only host = %q", got)
	}
	if got := joinName("host", ""); got != "host" {
		t.Errorf("join empty domain = %q", got)
	}
}

func TestNames_Split(t *testing.T) {
	domains := []string{"example.com", "internal.example.com"}
	cases := []struct {
		name       string
		wantHost   string
		wantDomain string
		wantErr    error
	}{
		{"app.example.com", "app", "example.com", nil},
		{"a.b.internal.example.com", "a.b", "internal.example.com", nil},
		{"App.Example.COM.", "app", "example.com", nil},
		{"badexample.com", "", "", ErrNameOutsideDomains},
		{"example.com", "", "", ErrApexName},
		{"*.example.com", "", "", ErrWildcard},
		{"other.org", "", "", ErrNameOutsideDomains},
		{"internal.example.com", "", "", ErrApexName},
		{"", "", "", ErrNameOutsideDomains},
		{"*.EXAMPLE.COM.", "", "", ErrWildcard},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, domain, err := splitName(tc.name, domains)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil || host != tc.wantHost || domain != tc.wantDomain {
				t.Errorf("split = (%q, %q, %v)", host, domain, err)
			}
		})
	}
}

func TestNames_InDomains(t *testing.T) {
	domains := []string{"example.com"}
	if !inDomains("x.example.com", domains) || inDomains("badexample.com", domains) || !inDomains("example.com", domains) {
		t.Error("inDomains label-boundary rule broken")
	}
	// inDomains trusts Config.Validate to have already normalised the
	// configured domains; a lingering trailing dot is not tolerated here.
	if inDomains("app.example.com", []string{"example.com."}) {
		t.Error("inDomains should not match against an un-normalised configured domain")
	}
}

func TestTTL_Clamp(t *testing.T) {
	for in, want := range map[endpoint.TTL]int64{-1: 0, 0: 0, 300: 300, 1 << 40: maxTTL} {
		if got := clampTTL(in); got != want {
			t.Errorf("clampTTL(%d) = %d, want %d", in, got, want)
		}
	}
	if ttlField(0) != "" || ttlField(300) != "300" {
		t.Error("ttlField")
	}
}
