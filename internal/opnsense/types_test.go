package opnsense

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/caarlos0/env/v11"
)

func validConfig() Config {
	return Config{
		Host: "https://fw.example.com", APIKey: "k", APISecret: "s",
		Domains:  []string{"Example.com.", "internal.example.com"},
		PageSize: 150, ReadAttempts: 3, ApplyWorkers: 4,
		RetryAttempts: 3, RetryInitialDelay: 500 * time.Millisecond, RetryMaxDelay: 10 * time.Second,
		RequestTimeout: 20 * time.Second, ReconfigureTimeout: 45 * time.Second, ApplyTimeout: 120 * time.Second,
		OwnerMarker: "external-dns",
	}
}

func TestConfig_ValidateNormalisesDomains(t *testing.T) {
	c := validConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.Domains[0] != "example.com" || c.Domains[1] != "internal.example.com" {
		t.Errorf("Domains = %v, want lower-cased without trailing dot", c.Domains)
	}
}

func TestConfig_ValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"host without scheme", func(c *Config) { c.Host = "fw.example.com" }},
		{"page size zero", func(c *Config) { c.PageSize = 0 }},
		{"page size too large", func(c *Config) { c.PageSize = 501 }},
		{"workers zero", func(c *Config) { c.ApplyWorkers = 0 }},
		{"workers too large", func(c *Config) { c.ApplyWorkers = 33 }},
		{"read attempts zero", func(c *Config) { c.ReadAttempts = 0 }},
		{"retry attempts zero", func(c *Config) { c.RetryAttempts = 0 }},
		{"retry max below initial", func(c *Config) { c.RetryMaxDelay = time.Millisecond }},
		{"empty domain", func(c *Config) { c.Domains = []string{""} }},
		{"leading dot", func(c *Config) { c.Domains = []string{".example.com"} }},
		{"no domains", func(c *Config) { c.Domains = nil }},
		{"apply timeout below reconfigure", func(c *Config) { c.ApplyTimeout = 10 * time.Second }},
		{"empty marker", func(c *Config) { c.OwnerMarker = "" }},
		{"request timeout non-positive", func(c *Config) { c.RequestTimeout = 0 }},
		{"reconfigure timeout non-positive", func(c *Config) { c.ReconfigureTimeout = 0 }},
		{"retry attempts too large", func(c *Config) { c.RetryAttempts = 11 }},
		{"retry initial delay too small", func(c *Config) { c.RetryInitialDelay = 0 }},
		{"domain double dot", func(c *Config) { c.Domains = []string{"example..com"} }},
		{"host with path", func(c *Config) { c.Host = "https://fw.example.com/index.php" }},
		{"duplicate domain", func(c *Config) { c.Domains = []string{"example.com", "Example.com."} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mut(&c)
			if err := c.Validate(); err == nil {
				t.Errorf("Validate accepted %s", tc.name)
			}
		})
	}
}

func TestConfig_DefaultsFromEnv(t *testing.T) {
	t.Setenv("OPNSENSE_HOST", "https://fw.example.com")
	t.Setenv("OPNSENSE_API_KEY", "k")
	t.Setenv("OPNSENSE_API_SECRET", "s")
	t.Setenv("OPNSENSE_DOMAINS", "example.com,internal.example.com")
	var c Config
	if err := env.Parse(&c); err != nil {
		t.Fatalf("env.Parse: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.PageSize != 150 || c.ApplyWorkers != 4 || c.ReadAttempts != 3 || c.AddPTR || c.SkipTLSVerify {
		t.Errorf("defaults wrong: %+v", c)
	}
	if c.RequestTimeout != 20*time.Second || c.ReconfigureTimeout != 45*time.Second || c.ApplyTimeout != 120*time.Second {
		t.Errorf("timeout defaults wrong: %+v", c)
	}
	if len(c.Domains) != 2 {
		t.Errorf("Domains = %v", c.Domains)
	}
}

func TestIsNetworkError(t *testing.T) {
	base := &NetworkError{Operation: "op", Err: errors.New("boom")}
	wrapped := fmt.Errorf("context: %w", base)
	if !IsNetworkError(wrapped) {
		t.Errorf("IsNetworkError(wrapped) = false, want true")
	}
	if IsNetworkError(errors.New("plain")) {
		t.Errorf("IsNetworkError(plain) = true, want false")
	}
}

func TestWriteError_DeterministicMessage(t *testing.T) {
	e := &WriteError{
		Operation: "set",
		Result:    "failed",
		Validations: map[string]StringOrList{
			"zeta":  {"z1", "z2"},
			"alpha": {"a1"},
		},
	}
	want := e.Error()
	for i := 0; i < 5; i++ {
		if got := e.Error(); got != want {
			t.Fatalf("Error() = %q, want %q (iteration %d)", got, want, i)
		}
	}
	alphaIdx := strings.Index(want, "alpha")
	zetaIdx := strings.Index(want, "zeta")
	if alphaIdx == -1 || zetaIdx == -1 || alphaIdx > zetaIdx {
		t.Errorf("Error() = %q, want fields listed in sorted order (alpha before zeta)", want)
	}
}
