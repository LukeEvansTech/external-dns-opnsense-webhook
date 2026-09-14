package opnsense

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	dialTimeout         = 10 * time.Second
	tlsHandshakeTimeout = 10 * time.Second
	idleConnTimeout     = 90 * time.Second
)

// newHTTPTransport builds the transport: TLS 1.2 minimum, an operator CA
// bundle winning over skip-verify, HTTP/2 attempted, and pools sized to the
// worker count so a wide apply cannot exhaust the firewall's connection table.
func newHTTPTransport(cfg *Config) (*http.Transport, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case cfg.CACertPath != "":
		pem, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("reading OPNSENSE_CA_CERT %q: %w", cfg.CACertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("OPNSENSE_CA_CERT %q: no certificates parsed", cfg.CACertPath)
		}
		tlsCfg.RootCAs = pool
		if cfg.SkipTLSVerify {
			slog.Warn("OPNSENSE_CA_CERT is set; ignoring OPNSENSE_SKIP_TLS_VERIFY")
		}
	case cfg.SkipTLSVerify:
		slog.Warn("TLS certificate verification is disabled (OPNSENSE_SKIP_TLS_VERIFY); set OPNSENSE_CA_CERT to verify the firewall")
		//nolint:gosec // Explicit opt-in for self-signed firewalls.
		tlsCfg.InsecureSkipVerify = true
	}

	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: dialTimeout}).DialContext,
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: cfg.RequestTimeout,
		IdleConnTimeout:       idleConnTimeout,
		MaxConnsPerHost:       cfg.ApplyWorkers + 2,
		MaxIdleConnsPerHost:   cfg.ApplyWorkers + 2,
	}, nil
}

// idempotentOps may be retried on 5xx and network errors: reads, and deletes
// (a repeated delete answers "not found", which the client treats as done).
var idempotentOps = map[string]bool{
	opSearchHostOverride: true,
	opGetHostOverride:    true,
	opDelHostOverride:    true,
	opServiceStatus:      true,
	opListLocalData:      true,
}

// retryAfter decides whether an attempt is retried and how long to wait.
// 429 is retried for any operation (the server rejected before processing).
// 5xx and network errors are retried only for idempotent operations: an add,
// set or reconfigure may have committed before the failure and the next
// reconcile converges it.
func (c *Client) retryAfter(op string, resp *http.Response, err error, attempt int) (bool, time.Duration) {
	if err != nil {
		if IsNetworkError(err) && idempotentOps[op] {
			return true, c.backoff(attempt, 0)
		}
		return false, 0
	}
	if resp == nil {
		return false, 0
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return true, c.backoff(attempt, parseRetryAfter(resp.Header.Get("Retry-After")))
	case resp.StatusCode >= 500 && resp.StatusCode < 600 && idempotentOps[op]:
		return true, c.backoff(attempt, 0)
	}
	return false, 0
}

// backoff is initial << attempt plus 0..50% jitter, clamped to max, never
// shorter than a server Retry-After hint.
func (c *Client) backoff(attempt int, hint time.Duration) time.Duration {
	initial := cmp.Or(c.cfg.RetryInitialDelay, 500*time.Millisecond)
	maxDelay := cmp.Or(c.cfg.RetryMaxDelay, 10*time.Second)
	base := initial << attempt
	if base <= 0 || base > maxDelay {
		base = maxDelay
	}
	var jitter time.Duration
	if half := int64(base) / 2; half > 0 {
		jitter = time.Duration(rand.Int64N(half))
	}
	wait := base + jitter
	if hint > wait {
		wait = hint
	}
	if wait > maxDelay {
		wait = maxDelay
	}
	return wait
}

func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if secs, err := strconv.Atoi(value); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
	}
	return 0
}

// sleep waits for d or until ctx is done.
func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
