// Package opnsense implements an external-dns provider over the OPNsense
// Unbound host-override API.
package opnsense

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Record types the provider reads or writes. CNAME is read-only knowledge:
// OPNsense has no CNAME record; aliases are rendered as copies of their parent.
const (
	recordTypeA    = "A"
	recordTypeAAAA = "AAAA"
	// recordTypeTXT and recordTypeMX are referenced by hostRow.target (dto.go).
	recordTypeTXT = "TXT"
	recordTypeMX  = "MX"
)

// Bounds on operator-tunable knobs.
const (
	maxPageSize          = 500
	maxApplyWorkers      = 32
	maxRetryAttempts     = 10
	minRetryInitialDelay = time.Millisecond
	// maxTXTBytes is both the model's txtdata limit (DescriptionField, 255)
	// and RFC 1035's character-string limit; they coincide because the
	// provider only accepts ASCII.
	maxTXTBytes = 255
	// maxTTL is the Unbound model's IntegerField ceiling for ttl.
	maxTTL = 2147483647
)

// Config is the provider configuration, read from the environment.
type Config struct {
	Host               string        `env:"OPNSENSE_HOST,notEmpty"`
	APIKey             string        `env:"OPNSENSE_API_KEY,notEmpty,unset"`
	APISecret          string        `env:"OPNSENSE_API_SECRET,notEmpty,unset"`
	Domains            []string      `env:"OPNSENSE_DOMAINS,notEmpty"            envSeparator:","`
	SkipTLSVerify      bool          `env:"OPNSENSE_SKIP_TLS_VERIFY"             envDefault:"false"`
	CACertPath         string        `env:"OPNSENSE_CA_CERT"                     envDefault:""`
	AddPTR             bool          `env:"OPNSENSE_ADD_PTR"                     envDefault:"false"`
	OwnerMarker        string        `env:"OPNSENSE_OWNER_MARKER"                envDefault:"external-dns"`
	PageSize           int           `env:"OPNSENSE_PAGE_SIZE"                   envDefault:"150"`
	ReadAttempts       int           `env:"OPNSENSE_READ_ATTEMPTS"               envDefault:"3"`
	ApplyWorkers       int           `env:"OPNSENSE_APPLY_WORKERS"               envDefault:"4"`
	RetryAttempts      int           `env:"OPNSENSE_RETRY_ATTEMPTS"              envDefault:"3"`
	RetryInitialDelay  time.Duration `env:"OPNSENSE_RETRY_INITIAL_DELAY"         envDefault:"500ms"`
	RetryMaxDelay      time.Duration `env:"OPNSENSE_RETRY_MAX_DELAY"             envDefault:"10s"`
	RequestTimeout     time.Duration `env:"OPNSENSE_REQUEST_TIMEOUT"             envDefault:"20s"`
	ReconfigureTimeout time.Duration `env:"OPNSENSE_RECONFIGURE_TIMEOUT"         envDefault:"45s"`
	ApplyTimeout       time.Duration `env:"OPNSENSE_APPLY_TIMEOUT"               envDefault:"120s"`
}

// Validate checks the configuration and normalises Domains (lower-case, no
// trailing dot) in place. It runs once at startup so a bad value fails the
// process instead of a reconcile.
func (c *Config) Validate() error {
	u, err := url.Parse(c.Host)
	if err != nil {
		return fmt.Errorf("OPNSENSE_HOST %q is not a valid URL: %w", c.Host, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("OPNSENSE_HOST %q must include a scheme and host (e.g. https://fw.example.com)", c.Host)
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("OPNSENSE_HOST %q must not include a path", c.Host)
	}
	c.Host = strings.TrimRight(c.Host, "/")

	if len(c.Domains) == 0 {
		return errors.New("OPNSENSE_DOMAINS must list at least one domain")
	}
	seen := make(map[string]bool, len(c.Domains))
	for i, d := range c.Domains {
		d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
		if d == "" || strings.HasPrefix(d, ".") || strings.Contains(d, "..") {
			return fmt.Errorf("OPNSENSE_DOMAINS entry %d (%q) is not a valid domain", i, c.Domains[i])
		}
		if seen[d] {
			return fmt.Errorf("OPNSENSE_DOMAINS entry %d (%q) is a duplicate", i, c.Domains[i])
		}
		seen[d] = true
		c.Domains[i] = d
	}
	if c.OwnerMarker == "" {
		return errors.New("OPNSENSE_OWNER_MARKER must not be empty")
	}
	if c.PageSize < 1 || c.PageSize > maxPageSize {
		return fmt.Errorf("OPNSENSE_PAGE_SIZE must be between 1 and %d, got %d", maxPageSize, c.PageSize)
	}
	if c.ReadAttempts < 1 {
		return fmt.Errorf("OPNSENSE_READ_ATTEMPTS must be at least 1, got %d", c.ReadAttempts)
	}
	if c.ApplyWorkers < 1 || c.ApplyWorkers > maxApplyWorkers {
		return fmt.Errorf("OPNSENSE_APPLY_WORKERS must be between 1 and %d, got %d", maxApplyWorkers, c.ApplyWorkers)
	}
	if c.RetryAttempts < 1 || c.RetryAttempts > maxRetryAttempts {
		return fmt.Errorf("OPNSENSE_RETRY_ATTEMPTS must be between 1 and %d, got %d", maxRetryAttempts, c.RetryAttempts)
	}
	if c.RetryInitialDelay < minRetryInitialDelay {
		return fmt.Errorf("OPNSENSE_RETRY_INITIAL_DELAY must be >= %s, got %s", minRetryInitialDelay, c.RetryInitialDelay)
	}
	if c.RetryMaxDelay < c.RetryInitialDelay {
		return fmt.Errorf("OPNSENSE_RETRY_MAX_DELAY (%s) must be >= OPNSENSE_RETRY_INITIAL_DELAY (%s)", c.RetryMaxDelay, c.RetryInitialDelay)
	}
	if c.RequestTimeout <= 0 || c.ReconfigureTimeout <= 0 {
		return errors.New("OPNSENSE_REQUEST_TIMEOUT and OPNSENSE_RECONFIGURE_TIMEOUT must be positive")
	}
	if c.ApplyTimeout <= c.ReconfigureTimeout {
		return fmt.Errorf("OPNSENSE_APPLY_TIMEOUT (%s) must exceed OPNSENSE_RECONFIGURE_TIMEOUT (%s)", c.ApplyTimeout, c.ReconfigureTimeout)
	}

	return nil
}
