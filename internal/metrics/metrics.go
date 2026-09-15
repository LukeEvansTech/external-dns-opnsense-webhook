package metrics

import (
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	namespace    = "externaldns_webhook"
	ProviderName = "opnsense"

	histogramBucketCount = 8

	// Prometheus label names reused across metric definitions.
	labelProvider = "provider"

	// Reasons AdjustEndpoints drops an endpoint. The set is closed because it
	// is a metric label; Provider.dropReason returns nothing outside it.
	DropReasonType          = "type"
	DropReasonSetIdentifier = "set-identifier"
	DropReasonWildcard      = "wildcard"
	DropReasonApex          = "apex"
	DropReasonDomain        = "domain"
	DropReasonName          = "name"
	DropReasonTXT           = "txt"

	reconfigureOK    = "ok"
	reconfigureError = "error"
	labelEndpoint    = "endpoint"
	labelRecordType  = "record_type"
	labelOperation   = "operation"
	labelMethod      = "method"
)

// Metrics holds all Prometheus metrics for the webhook.
type Metrics struct {
	// HTTP metrics
	HTTPRequestsTotal         *prometheus.CounterVec
	HTTPRequestDuration       *prometheus.HistogramVec
	HTTPRequestsInFlight      *prometheus.GaugeVec
	HTTPResponseSizeBytes     *prometheus.HistogramVec
	HTTPValidationErrorsTotal *prometheus.CounterVec
	HTTPJSONErrorsTotal       *prometheus.CounterVec

	// Business metrics - DNS records
	RecordsTotal       *prometheus.GaugeVec
	ChangesTotal       *prometheus.CounterVec
	ChangesByTypeTotal *prometheus.CounterVec
	BatchSize          *prometheus.HistogramVec

	// Endpoint operations
	AdjustEndpointsTotal *prometheus.CounterVec
	NegotiateTotal       *prometheus.CounterVec

	// OPNsense API metrics
	APIErrorsTotal       *prometheus.CounterVec
	APIDuration          *prometheus.HistogramVec
	APIResponseSizeBytes *prometheus.HistogramVec
	APIRetriesTotal      *prometheus.CounterVec
	APIRateLimitsTotal   *prometheus.CounterVec
	PanicsTotal          *prometheus.CounterVec

	// OPNsense provider metrics
	PagesFetchedTotal      *prometheus.CounterVec
	ReadRestartsTotal      *prometheus.CounterVec
	RowsTotal              *prometheus.GaugeVec
	ReconfigureTotal       *prometheus.CounterVec
	PendingReconfigure     *prometheus.GaugeVec
	ApplyDuration          *prometheus.HistogramVec
	DeleteBlockedTotal     *prometheus.CounterVec
	EndpointsDroppedTotal  *prometheus.CounterVec
	TXTInvalidTotal        *prometheus.CounterVec
	LostWritesTotal        *prometheus.CounterVec
	VerifyReadsFailedTotal *prometheus.CounterVec

	// Quality metrics
	ConsecutiveErrors    *prometheus.GaugeVec
	LastSuccessTimestamp *prometheus.GaugeVec

	// Info metric
	Info *prometheus.GaugeVec
}

var (
	initOnce sync.Once
	instance *Metrics
)

// New initialises the package-wide metrics instance against the default
// Prometheus registerer. Safe to call multiple times — only the first call
// performs initialisation, and the supplied version is recorded then.
func New(version string) *Metrics {
	initOnce.Do(func() {
		instance = build(promauto.With(prometheus.DefaultRegisterer), version)
	})

	return instance
}

// Get returns the singleton metrics instance, initialising it with an
// "unknown" version if New has not yet been called.
func Get() *Metrics {
	return New("unknown")
}

// build constructs a Metrics instance against the supplied factory. Exposed
// for tests that need an isolated registry.
//
//nolint:funlen // Metric registration is declarative and splitting would reduce readability
func build(f promauto.Factory, version string) *Metrics {
	m := &Metrics{
		HTTPRequestsTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "http_requests_total",
				Help:      "Total number of HTTP requests",
			},
			[]string{labelProvider, labelMethod, labelEndpoint, "status_code"},
		),
		HTTPRequestDuration: f.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "http_request_duration_seconds",
				Help:      "HTTP request duration in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{labelProvider, labelMethod, labelEndpoint},
		),
		HTTPRequestsInFlight: f.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "http_requests_in_flight",
				Help:      "Number of HTTP requests currently being processed",
			},
			[]string{labelProvider},
		),
		HTTPResponseSizeBytes: f.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "http_response_size_bytes",
				Help:      "HTTP response size in bytes",
				Buckets:   prometheus.ExponentialBuckets(100, 10, histogramBucketCount),
			},
			[]string{labelProvider, labelMethod, labelEndpoint},
		),
		HTTPValidationErrorsTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "http_validation_errors_total",
				Help:      "Total number of HTTP header validation errors",
			},
			[]string{labelProvider, "header_type"},
		),
		HTTPJSONErrorsTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "http_json_errors_total",
				Help:      "Total number of JSON decoding errors",
			},
			[]string{labelProvider, labelEndpoint},
		),

		RecordsTotal: f.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "records",
				Help:      "Current number of DNS records by type",
			},
			[]string{labelProvider, labelRecordType},
		),
		ChangesTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "changes_total",
				Help:      "Total number of DNS changes",
			},
			[]string{labelProvider, labelOperation},
		),
		ChangesByTypeTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "changes_by_type_total",
				Help:      "Total number of DNS changes by record type",
			},
			[]string{labelProvider, labelOperation, labelRecordType},
		),
		BatchSize: f.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "batch_size",
				Help:      "Size of change batches",
				Buckets:   prometheus.ExponentialBuckets(1, 2, 10),
			},
			[]string{labelProvider, labelOperation},
		),

		AdjustEndpointsTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "adjust_endpoints_total",
				Help:      "Total number of adjust endpoints calls",
			},
			[]string{labelProvider},
		),
		NegotiateTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "negotiate_total",
				Help:      "Total number of negotiate calls",
			},
			[]string{labelProvider},
		),

		APIErrorsTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "opnsense_api_errors_total",
				Help:      "Total number of OPNsense API errors",
			},
			[]string{labelProvider, labelOperation},
		),
		APIDuration: f.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "opnsense_api_duration_seconds",
				Help:      "OPNsense API request duration in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{labelProvider, labelOperation},
		),
		APIResponseSizeBytes: f.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "opnsense_api_response_size_bytes",
				Help:      "OPNsense API response size in bytes",
				Buckets:   prometheus.ExponentialBuckets(100, 10, histogramBucketCount),
			},
			[]string{labelOperation},
		),
		APIRetriesTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "opnsense_api_retries_total",
				Help:      "Total number of OPNsense API retries triggered by 5xx or 429 responses",
			},
			[]string{labelProvider, labelOperation, "status"},
		),
		APIRateLimitsTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "opnsense_api_rate_limits_total",
				Help:      "Total number of HTTP 429 rate-limit responses received from OPNsense",
			},
			[]string{labelProvider, labelOperation},
		),
		PanicsTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "http_handler_panics_total",
				Help:      "Total number of panics caught by the HTTP recovery middleware",
			},
			[]string{labelProvider, labelEndpoint},
		),

		PagesFetchedTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "opnsense_pages_fetched_total",
				Help:      "Total number of searchHostOverride pages fetched",
			},
			[]string{labelProvider},
		),
		ReadRestartsTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "opnsense_read_restarts_total",
				Help:      "Total number of paginated reads restarted because the table changed mid-read",
			},
			[]string{labelProvider},
		),
		RowsTotal: f.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "opnsense_rows",
				Help:      "Host override rows in the last accepted snapshot (all rows, before filtering)",
			},
			[]string{labelProvider},
		),
		ReconfigureTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "opnsense_reconfigure_total",
				Help:      "Total number of Unbound reconfigure calls by result",
			},
			[]string{labelProvider, "result"},
		),
		PendingReconfigure: f.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "opnsense_pending_reconfigure",
				Help:      "1 while saved configuration has not been applied to the running Unbound",
			},
			[]string{labelProvider},
		),
		ApplyDuration: f.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "opnsense_apply_duration_seconds",
				Help:      "Wall time of one ApplyChanges including reconfigure",
				Buckets:   prometheus.ExponentialBuckets(0.5, 2, 9),
			},
			[]string{labelProvider},
		),
		DeleteBlockedTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "opnsense_delete_blocked_total",
				Help:      "Deletes refused because the row has alias children",
			},
			[]string{labelProvider},
		),
		EndpointsDroppedTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "opnsense_endpoints_dropped_total",
				Help:      "Desired endpoints dropped in AdjustEndpoints by reason",
			},
			[]string{labelProvider, "reason"},
		),
		TXTInvalidTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "opnsense_txt_invalid_total",
				Help:      "TXT endpoints refused for length or content",
			},
			[]string{labelProvider},
		),
		LostWritesTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "opnsense_lost_writes_total",
				Help:      "Writes OPNsense acknowledged that a re-read of the table showed were not saved, by operation",
			},
			[]string{labelProvider, labelOperation},
		),
		VerifyReadsFailedTotal: f.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "opnsense_verify_reads_failed_total",
				Help:      "Post-phase verification reads that failed, leaving that apply's writes unverified",
			},
			[]string{labelProvider},
		),

		ConsecutiveErrors: f.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "consecutive_errors",
				Help:      "Number of consecutive errors",
			},
			[]string{labelProvider},
		),
		LastSuccessTimestamp: f.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "last_success_timestamp",
				Help:      "Timestamp of last successful operation",
			},
			[]string{labelProvider},
		),
		Info: f.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "info",
				Help:      "Information about the webhook instance",
			},
			[]string{"version", labelProvider},
		),
	}

	m.Info.WithLabelValues(version, ProviderName).Set(1)
	m.preCreateChildren()

	return m
}

// DropReasons lists every value the endpoints_dropped reason label can take.
var DropReasons = []string{
	DropReasonType,
	DropReasonSetIdentifier,
	DropReasonWildcard,
	DropReasonApex,
	DropReasonDomain,
	DropReasonName,
	DropReasonTXT,
}

// preCreateChildren creates the counter children whose label sets are closed,
// so each series exists at zero from startup. A counter that first appears
// mid-window with a non-zero value has no earlier sample for increase() or
// rate() to diff against, and its first increment is invisible to an alert;
// starting every known series at zero makes the first increment a real delta.
func (m *Metrics) preCreateChildren() {
	m.DeleteBlockedTotal.WithLabelValues(ProviderName)
	m.TXTInvalidTotal.WithLabelValues(ProviderName)
	m.VerifyReadsFailedTotal.WithLabelValues(ProviderName)
	m.PagesFetchedTotal.WithLabelValues(ProviderName)
	m.ReadRestartsTotal.WithLabelValues(ProviderName)
	for _, result := range []string{reconfigureOK, reconfigureError} {
		m.ReconfigureTotal.WithLabelValues(ProviderName, result)
	}
	for _, reason := range DropReasons {
		m.EndpointsDroppedTotal.WithLabelValues(ProviderName, reason)
	}
	for _, op := range []string{"create", "update", "delete"} {
		m.ChangesTotal.WithLabelValues(ProviderName, op)
		m.LostWritesTotal.WithLabelValues(ProviderName, op)
	}
}

// RecordHTTPRequest records HTTP request metrics.
func (m *Metrics) RecordHTTPRequest(method, endpoint string, statusCode int, duration time.Duration, responseSize int) {
	m.HTTPRequestsTotal.WithLabelValues(ProviderName, method, endpoint, strconv.Itoa(statusCode)).Inc()
	m.HTTPRequestDuration.WithLabelValues(ProviderName, method, endpoint).Observe(duration.Seconds())
	if responseSize > 0 {
		m.HTTPResponseSizeBytes.WithLabelValues(ProviderName, method, endpoint).Observe(float64(responseSize))
	}
}

// RecordAPICall records OPNsense API call metrics.
func (m *Metrics) RecordAPICall(operation string, duration time.Duration, responseSize int, err error) {
	m.APIDuration.WithLabelValues(ProviderName, operation).Observe(duration.Seconds())
	if responseSize > 0 {
		m.APIResponseSizeBytes.WithLabelValues(operation).Observe(float64(responseSize))
	}
	if err != nil {
		m.APIErrorsTotal.WithLabelValues(ProviderName, operation).Inc()
	}
}

// RecordReconfigure counts one Unbound reconfigure attempt by outcome.
func (m *Metrics) RecordReconfigure(err error) {
	result := reconfigureOK
	if err != nil {
		result = reconfigureError
	}
	m.ReconfigureTotal.WithLabelValues(ProviderName, result).Inc()
}

// RecordOperation records the outcome of one top-level provider operation (a
// full Records or ApplyChanges). The consecutive-error and last-success gauges
// are tracked here — per operation — rather than in RecordAPICall: a
// single ApplyChanges fans out many concurrent OPNsense API calls, and updating
// these gauges from each of them races. One worker's success could Set the
// count to 0 while its siblings are still failing, so "consecutive" lost all
// meaning and an alert on consecutive_errors could silently never fire during a
// failing batch. Per-operation accounting keeps it honest; per-call failures
// are still counted unambiguously by APIErrorsTotal.
func (m *Metrics) RecordOperation(err error) {
	if err != nil {
		m.ConsecutiveErrors.WithLabelValues(ProviderName).Inc()

		return
	}
	m.ConsecutiveErrors.WithLabelValues(ProviderName).Set(0)
	m.LastSuccessTimestamp.WithLabelValues(ProviderName).Set(float64(time.Now().Unix()))
}

// UpdateRecordsByType updates the records count by type.
func (m *Metrics) UpdateRecordsByType(recordType string, count int) {
	m.RecordsTotal.WithLabelValues(ProviderName, recordType).Set(float64(count))
}

// RecordChange records a DNS change operation.
func (m *Metrics) RecordChange(operation, recordType string) {
	m.ChangesTotal.WithLabelValues(ProviderName, operation).Inc()
	m.ChangesByTypeTotal.WithLabelValues(ProviderName, operation, recordType).Inc()
}
