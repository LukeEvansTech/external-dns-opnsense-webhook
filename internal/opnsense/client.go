package opnsense

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/LukeEvansTech/external-dns-opnsense-webhook/internal/metrics"
	extdnshttp "sigs.k8s.io/external-dns/pkg/http"
)

// Operation names: bounded metric labels and the retry policy key.
const (
	opSearchHostOverride = "search_host_override"
	opGetHostOverride    = "get_host_override"
	opAddHostOverride    = "add_host_override"
	opSetHostOverride    = "set_host_override"
	opDelHostOverride    = "del_host_override"
	opReconfigure        = "reconfigure"
	opServiceStatus      = "service_status"
	opListLocalData      = "list_local_data"
)

const (
	pathSearch      = "/api/unbound/settings/searchHostOverride"
	pathGet         = "/api/unbound/settings/getHostOverride/"
	pathAdd         = "/api/unbound/settings/addHostOverride"
	pathSet         = "/api/unbound/settings/setHostOverride/"
	pathDel         = "/api/unbound/settings/delHostOverride/"
	pathReconfigure = "/api/unbound/service/reconfigure"
	pathStatus      = "/api/unbound/service/status"
	pathListLocal   = "/api/unbound/diagnostics/listlocaldata"

	errorBodyBufSize = 512
)

// maxResponseBytes caps a response body. A full 26.7 table of a few hundred
// rows is under 100 KiB; 8 MiB leaves room for large alias trees.
var maxResponseBytes int64 = 8 << 20

// maxLocalDataBytes caps listlocaldata, the one endpoint that is not
// paginated: it dumps every name Unbound serves, host overrides and DHCP
// leases alike, so its response scales with the whole resolver rather than
// with this provider's rows. 64 MiB is roughly a million entries.
const maxLocalDataBytes int64 = 64 << 20

// sortAsc is the ascending sort direction OPNsense's searchHostOverride
// endpoint expects; every sort field below uses it.
const sortAsc = "asc"

// searchSort is the deterministic order for paginated reads. OPNsense appends
// each row's uuid to the composite key, so ties are broken the same way on
// every page. encoding/json marshals map keys in sorted order, so the wire
// order of this map is always fixed: domain, hostname, rr, server.
var searchSort = map[string]string{"domain": sortAsc, "hostname": sortAsc, "rr": sortAsc, "server": sortAsc}

// Client calls the OPNsense Unbound settings and service API.
type Client struct {
	cfg   *Config
	httpc *http.Client
}

// NewClient builds a client; it performs no I/O.
func NewClient(cfg *Config) (*Client, error) {
	transport, err := newHTTPTransport(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, httpc: &http.Client{Transport: transport}}, nil
}

// do issues one operation with the retry policy, returning the decoded
// body. Every attempt runs under a per-call timeout derived from ctx.
// maxBytes caps the response body; all callers pass maxResponseBytes except
// ListLocalData, whose response is not paginated.
func (c *Client) do(ctx context.Context, op, method, path string, body []byte, dest any, maxBytes int64) (err error) {
	start := time.Now()
	var size int
	defer func() { metrics.Get().RecordAPICall(op, time.Since(start), size, err) }()

	attempts := max(c.cfg.RetryAttempts, 1)
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
		}
		resp, derr := c.once(ctx, op, method, path, body)
		if derr == nil && resp.StatusCode < 400 {
			size, err = decodeBody(resp, op, dest, maxBytes)
			// A body-read or decode failure here is returned as-is, not fed
			// back into the retry policy: a 2xx with an unreadable or
			// malformed body signals a data-shape problem (a bug or an API
			// change), not a transient failure, so retrying it would not help.
			return err
		}
		if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
			metrics.Get().APIRateLimitsTotal.WithLabelValues(metrics.ProviderName, op).Inc()
		}
		retryable, wait := c.retryAfter(op, resp, derr, attempt)
		if !retryable || attempt == attempts-1 {
			if derr != nil {
				return derr
			}
			return apiError(resp, op)
		}
		if resp != nil {
			extdnshttp.DrainAndClose(resp.Body)
		}
		status := "network"
		if resp != nil {
			status = strconv.Itoa(resp.StatusCode)
		}
		metrics.Get().APIRetriesTotal.WithLabelValues(metrics.ProviderName, op, status).Inc()
		slog.Debug("retrying opnsense request", "operation", op, "attempt", attempt+1, "wait", wait, "status", status)
		if serr := sleep(ctx, wait); serr != nil {
			return serr
		}
	}
}

func (c *Client) once(ctx context.Context, op, method, path string, body []byte) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.Host+path, reader)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("opnsense: building request: %w", err)
	}
	req.SetBasicAuth(c.cfg.APIKey, c.cfg.APISecret)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		cancel()
		return nil, &NetworkError{Operation: op, Err: err}
	}
	// The body is read by the caller; release the timeout when it is closed.
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	c.cancel()
	return c.ReadCloser.Close()
}

func decodeBody(resp *http.Response, op string, dest any, maxBytes int64) (int, error) {
	defer extdnshttp.DrainAndClose(resp.Body)
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return 0, &DataError{Operation: op, Err: err}
	}
	if int64(len(raw)) > maxBytes {
		return len(raw), &DataError{Operation: op, Err: fmt.Errorf("response exceeds %d bytes", maxBytes)}
	}
	if dest == nil {
		return len(raw), nil
	}
	if err := json.Unmarshal(raw, dest); err != nil {
		return len(raw), &DataError{Operation: op, Err: err}
	}
	return len(raw), nil
}

func apiError(resp *http.Response, op string) error {
	defer extdnshttp.DrainAndClose(resp.Body)
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyBufSize))
	return &APIError{Operation: op, StatusCode: resp.StatusCode, Message: string(bytes.TrimSpace(raw))}
}

// SearchHostOverrides fetches one page in the deterministic sort order.
func (c *Client) SearchHostOverrides(ctx context.Context, current, rowCount int) (searchPage, error) {
	body, err := json.Marshal(searchRequest{Current: current, RowCount: rowCount, Sort: searchSort})
	if err != nil {
		return searchPage{}, &DataError{Operation: opSearchHostOverride, Err: err}
	}
	var page searchPage
	if err := c.do(ctx, opSearchHostOverride, http.MethodPost, pathSearch, body, &page, maxResponseBytes); err != nil {
		return searchPage{}, err
	}
	metrics.Get().PagesFetchedTotal.WithLabelValues(metrics.ProviderName).Inc()
	return page, nil
}

// GetHostOverride fetches one row by uuid. This endpoint does not answer in
// searchHostOverride's shape: it expands every select field into the whole
// option set — rr arrives as {"A":{"value":"A (IPv4 address)","selected":1},
// "AAAA":{...},...} — and adds an aliases option set that nothing models.
// hostRow's decoder resolves the expanded form back to the selected key, so
// the row returned here compares with one read from a search page. The body
// carries no uuid, so the one asked for is filled in below.
func (c *Client) GetHostOverride(ctx context.Context, id string) (hostRow, error) {
	var out getHostResponse
	if err := c.do(ctx, opGetHostOverride, http.MethodGet, pathGet+id, nil, &out, maxResponseBytes); err != nil {
		return hostRow{}, err
	}
	// getHostOverride answers {} for an unknown uuid rather than a 404, so an
	// empty hostname and rr together is the only signal that the row does not
	// exist. This relies on rr being a mandatory field on every real host row,
	// and the empty rr survives the option decoding: an absent field is never
	// an option set, so it stays the empty key rather than failing to resolve.
	if out.Host.Hostname == "" && out.Host.RR == "" {
		return hostRow{}, &APIError{Operation: opGetHostOverride, StatusCode: http.StatusNotFound, Message: "no such uuid " + id}
	}
	out.Host.UUID = id
	return out.Host, nil
}

// AddHostOverride creates a row and returns its uuid.
func (c *Client) AddHostOverride(ctx context.Context, h hostFields) (string, error) {
	body, err := json.Marshal(hostPayload{Host: h})
	if err != nil {
		return "", &DataError{Operation: opAddHostOverride, Err: err}
	}
	var out writeResponse
	if err := c.do(ctx, opAddHostOverride, http.MethodPost, pathAdd, body, &out, maxResponseBytes); err != nil {
		return "", err
	}
	if err := out.err(opAddHostOverride); err != nil {
		return "", err
	}
	return out.UUID, nil
}

// SetHostOverride replaces a row's fields in place, keeping its uuid and aliases.
func (c *Client) SetHostOverride(ctx context.Context, id string, h hostFields) error {
	body, err := json.Marshal(hostPayload{Host: h})
	if err != nil {
		return &DataError{Operation: opSetHostOverride, Err: err}
	}
	var out writeResponse
	if err := c.do(ctx, opSetHostOverride, http.MethodPost, pathSet+id, body, &out, maxResponseBytes); err != nil {
		return err
	}
	return out.err(opSetHostOverride)
}

// DelHostOverride deletes a row (and, on the firewall, its aliases). It
// returns false when the row was already gone.
func (c *Client) DelHostOverride(ctx context.Context, id string) (bool, error) {
	var out writeResponse
	if err := c.do(ctx, opDelHostOverride, http.MethodPost, pathDel+id, []byte("{}"), &out, maxResponseBytes); err != nil {
		return false, err
	}
	switch out.Result {
	case "deleted":
		return true, nil
	case "not found":
		return false, nil
	default:
		return false, out.err(opDelHostOverride)
	}
}

// Reconfigure applies the saved configuration to the running Unbound.
func (c *Client) Reconfigure(ctx context.Context) error {
	var out statusResponse
	if err := c.do(ctx, opReconfigure, http.MethodPost, pathReconfigure, []byte("{}"), &out, maxResponseBytes); err != nil {
		return err
	}
	if out.Status != "ok" {
		return &APIError{Operation: opReconfigure, StatusCode: http.StatusOK, Message: "status " + strconv.Quote(out.Status)}
	}
	return nil
}

// ServiceStatus checks the API answers and Unbound reports a status.
func (c *Client) ServiceStatus(ctx context.Context) error {
	var out statusResponse
	if err := c.do(ctx, opServiceStatus, http.MethodGet, pathStatus, nil, &out, maxResponseBytes); err != nil {
		return err
	}
	if out.Status == "" {
		return &APIError{Operation: opServiceStatus, StatusCode: http.StatusOK, Message: "empty status"}
	}
	return nil
}

// ListLocalData returns what Unbound is currently serving. Unlike every other
// read here it is not paginated — one call dumps the whole served table, which
// includes names this provider never wrote (other host overrides, DHCP
// registrations) — so it gets maxLocalDataBytes rather than the ordinary cap.
//
// A served table larger than that cap fails with a DataError naming the limit,
// which makes the startup served-state check fail and log its cause. That
// check is best-effort: it only decides whether to issue one repair
// reconfigure, so losing it leaves reads and applies working normally.
func (c *Client) ListLocalData(ctx context.Context) ([]localData, error) {
	var out localDataResponse
	if err := c.do(ctx, opListLocalData, http.MethodPost, pathListLocal, []byte("{}"), &out, maxLocalDataBytes); err != nil {
		return nil, err
	}
	return out.Data, nil
}
