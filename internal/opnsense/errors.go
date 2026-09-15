package opnsense

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Sentinel errors callers branch on.
var (
	// ErrAliasChildren is returned when a delete would cascade to alias rows
	// the provider does not own.
	ErrAliasChildren = errors.New("opnsense: row has alias children; refusing to delete")
	// ErrInconsistentRead is returned when a paginated read could not be
	// accepted within OPNSENSE_READ_ATTEMPTS.
	ErrInconsistentRead = errors.New("opnsense: host override table changed during read")
	// ErrTXTInvalid is returned for a TXT target the model or DNS cannot hold.
	ErrTXTInvalid = errors.New("opnsense: invalid TXT value")
	// ErrNameOutsideDomains is returned for a name not under OPNSENSE_DOMAINS.
	ErrNameOutsideDomains = errors.New("opnsense: name is outside the configured domains")
	// ErrApexName is returned for a name equal to a configured domain.
	ErrApexName = errors.New("opnsense: apex names cannot be host overrides")
	// ErrWildcard is returned for a wildcard name on write.
	ErrWildcard = errors.New("opnsense: wildcard overrides are not written in v1")
	// ErrUnsupportedType is returned for a record type the provider cannot write.
	ErrUnsupportedType = errors.New("opnsense: unsupported record type")
	// ErrLostWrite is returned when the firewall acknowledged a write that a
	// re-read of the table shows was not saved.
	ErrLostWrite = errors.New("opnsense: write acknowledged but not saved")
)

// NetworkError wraps a transport failure.
type NetworkError struct {
	Operation string
	Err       error
}

func (e *NetworkError) Error() string {
	return fmt.Sprintf("opnsense: network error during %s: %v", e.Operation, e.Err)
}
func (e *NetworkError) Unwrap() error { return e.Err }

// APIError represents an HTTP response the caller could not treat as
// successful: a non-2xx status, or a 2xx response whose body reports a
// non-ok status. Check StatusCode rather than assuming it is outside the
// 2xx range.
type APIError struct {
	Operation  string
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("opnsense: API error during %s (status %d): %s", e.Operation, e.StatusCode, e.Message)
}

// DataError is a body that could not be read or decoded.
type DataError struct {
	Operation string
	Err       error
}

func (e *DataError) Error() string {
	return fmt.Sprintf("opnsense: data error during %s: %v", e.Operation, e.Err)
}
func (e *DataError) Unwrap() error { return e.Err }

// WriteError is a 200 response whose body reports a failed write, carrying
// the model's validation messages verbatim.
type WriteError struct {
	Operation   string
	Result      string
	Validations map[string]StringOrList
}

func (e *WriteError) Error() string {
	if len(e.Validations) == 0 {
		return fmt.Sprintf("opnsense: %s returned result %q", e.Operation, e.Result)
	}
	fields := make([]string, 0, len(e.Validations))
	for field := range e.Validations {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		parts = append(parts, field+": "+strings.Join(e.Validations[field], "; "))
	}
	return fmt.Sprintf("opnsense: %s returned result %q (%s)", e.Operation, e.Result, strings.Join(parts, ", "))
}

// IsNetworkError reports whether err is a *NetworkError.
func IsNetworkError(err error) bool {
	_, ok := errors.AsType[*NetworkError](err)
	return ok
}
