package opnsense

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestParseRetryAfter(t *testing.T) {
	// http.TimeFormat's layout has a literal "GMT" suffix rather than a zone
	// directive, so a local (non-UTC) time.Time must be converted first or
	// the formatted string silently mislabels local wall-clock time as GMT.
	past := time.Now().Add(-2 * time.Minute).UTC()

	cases := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{name: "empty", value: "", want: 0},
		{name: "zero", value: "0", want: 0},
		{name: "120 seconds", value: "120", want: 120 * time.Second},
		{name: "negative", value: "-1", want: 0},
		{name: "not a number or date", value: "abc", want: 0},
		{name: "past HTTP-date", value: past.Format(http.TimeFormat), want: 0},
		{name: "huge value capped at a day", value: "99999999999", want: maxRetryAfterSeconds * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseRetryAfter(tc.value)
			if got != tc.want {
				t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}

	t.Run("future HTTP-date", func(t *testing.T) {
		future := time.Now().Add(2 * time.Minute).UTC()
		want := time.Until(future)
		got := parseRetryAfter(future.Format(http.TimeFormat))
		diff := got - want
		if diff < 0 {
			diff = -diff
		}
		if diff > time.Second {
			t.Errorf("parseRetryAfter(future) = %v, want ~%v (within 1s)", got, want)
		}
	})
}

func TestClient_Backoff(t *testing.T) {
	// testClient (client_test.go) builds from validConfig() with
	// RetryInitialDelay=1ms, RetryMaxDelay=5ms.
	c := testClient(t, "https://fw.example.com")

	t.Run("attempt 0, no hint", func(t *testing.T) {
		wait := c.backoff(0, 0)
		if wait < time.Millisecond || wait > 1500*time.Microsecond {
			t.Errorf("backoff(0, 0) = %v, want within [1ms, 1.5ms]", wait)
		}
	})

	t.Run("attempt 20 clamps to the max delay", func(t *testing.T) {
		wait := c.backoff(20, 0)
		if wait != c.cfg.RetryMaxDelay {
			t.Errorf("backoff(20, 0) = %v, want %v", wait, c.cfg.RetryMaxDelay)
		}
	})

	t.Run("hint above the computed wait wins", func(t *testing.T) {
		const hint = 3 * time.Millisecond
		wait := c.backoff(0, hint)
		if wait < hint {
			t.Errorf("backoff(0, %v) = %v, want >= %v", hint, wait, hint)
		}
	})

	t.Run("hint beyond the max delay is clamped to it", func(t *testing.T) {
		wait := c.backoff(0, time.Hour)
		if wait != c.cfg.RetryMaxDelay {
			t.Errorf("backoff(0, 1h) = %v, want %v (the max delay)", wait, c.cfg.RetryMaxDelay)
		}
	})
}

func TestClient_RetryAfterDecision(t *testing.T) {
	c := testClient(t, "https://fw.example.com")
	netErr := &NetworkError{Operation: "test", Err: errors.New("boom")}

	cases := []struct {
		name      string
		op        string
		resp      *http.Response
		err       error
		wantRetry bool
	}{
		{name: "network error, idempotent op", op: opSearchHostOverride, err: netErr, wantRetry: true},
		{name: "network error, non-idempotent op", op: opAddHostOverride, err: netErr, wantRetry: false},
		{name: "429, non-idempotent op", op: opAddHostOverride, resp: &http.Response{StatusCode: http.StatusTooManyRequests}, wantRetry: true},
		{name: "500, idempotent op", op: opSearchHostOverride, resp: &http.Response{StatusCode: http.StatusInternalServerError}, wantRetry: true},
		{name: "500, non-idempotent op", op: opSetHostOverride, resp: &http.Response{StatusCode: http.StatusInternalServerError}, wantRetry: false},
		{name: "404, any op", op: opSearchHostOverride, resp: &http.Response{StatusCode: http.StatusNotFound}, wantRetry: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			retry, _ := c.retryAfter(tc.op, tc.resp, tc.err, 0)
			if retry != tc.wantRetry {
				t.Errorf("retryAfter(%s) retry = %v, want %v", tc.op, retry, tc.wantRetry)
			}
		})
	}
}
