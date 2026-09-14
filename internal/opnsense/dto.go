package opnsense

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// flexBool decodes the JSON true/false and "0"/"1"/bare-number spellings
// OPNsense's model layer produces for a boolean field. In this package it
// decodes isAlias only; enabled and addptr stay raw strings on hostRow, with
// enabled read through hostRow.enabled() rather than a flexBool field.
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	s := strings.Trim(strings.TrimSpace(string(data)), `"`)
	switch s {
	case "true", "1":
		*b = true
	case "false", "0", "", "null":
		*b = false
	default:
		return fmt.Errorf("opnsense: cannot decode %q as bool", s)
	}
	return nil
}

// StringOrList decodes a validations value that is either one message or a
// list of messages; ApiMutableModelControllerBase switches to a list when a
// field collects a second message.
type StringOrList []string

func (s *StringOrList) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*s = StringOrList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("opnsense: validations value is neither string nor list: %w", err)
	}
	*s = StringOrList(many)
	return nil
}

// hostRow is one row of searchHostOverride (26.1+ tree view) or the body of
// getHostOverride. Alias children carry the parent's rr/server/ttl and their
// own hostname/domain/description; an empty hostname or domain on a child
// means "inherit from the parent" (unbound.inc).
//
//nolint:tagliatelle // OPNsense field names cannot be changed
type hostRow struct {
	UUID        string    `json:"uuid"`
	Enabled     string    `json:"enabled"`
	Hostname    string    `json:"hostname"`
	Domain      string    `json:"domain"`
	RR          string    `json:"rr"`
	Server      string    `json:"server"`
	TXTData     string    `json:"txtdata"`
	MX          string    `json:"mx"`
	MXPrio      string    `json:"mxprio"`
	TTL         string    `json:"ttl"`
	AddPTR      string    `json:"addptr"`
	Description string    `json:"description"`
	IsAlias     flexBool  `json:"isAlias"`
	Children    []hostRow `json:"_children"`
}

func (r hostRow) enabled() bool { return r.Enabled != "0" && r.Enabled != "" }

// ttlValue returns the row's TTL or 0 when unset.
func (r hostRow) ttlValue() int64 {
	if r.TTL == "" {
		return 0
	}
	n, err := strconv.ParseInt(r.TTL, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// target is the endpoint target this row represents.
func (r hostRow) target() string {
	switch r.RR {
	case recordTypeTXT:
		return restoreTXTQuotes(r.TXTData)
	case recordTypeMX:
		return r.MXPrio + " " + r.MX
	default:
		return r.Server
	}
}

// searchPage is the searchHostOverride response envelope.
//
//nolint:tagliatelle // OPNsense field names cannot be changed
type searchPage struct {
	Rows     []hostRow `json:"rows"`
	RowCount int       `json:"rowCount"`
	Total    int       `json:"total"`
	Current  int       `json:"current"`
}

// searchRequest is the searchHostOverride POST body. sort is a map of field
// to direction; OPNsense uses every key as a sort field and the first key's
// direction, then appends the row uuid as a tie-breaker.
type searchRequest struct {
	Current      int               `json:"current"`
	RowCount     int               `json:"rowCount"`
	Sort         map[string]string `json:"sort,omitempty"`
	SearchPhrase string            `json:"searchPhrase"`
}

// hostFields is the body of addHostOverride and setHostOverride.
type hostFields struct {
	Enabled     string `json:"enabled"`
	Hostname    string `json:"hostname"`
	Domain      string `json:"domain"`
	RR          string `json:"rr"`
	Server      string `json:"server"`
	TXTData     string `json:"txtdata"`
	TTL         string `json:"ttl"`
	AddPTR      string `json:"addptr"`
	Description string `json:"description"`
}

type hostPayload struct {
	Host hostFields `json:"host"`
}

type getHostResponse struct {
	Host hostRow `json:"host"`
}

// writeResponse is the body of add/set/del: result plus, on failure, the
// validation messages keyed by "host.<field>".
type writeResponse struct {
	Result      string                  `json:"result"`
	UUID        string                  `json:"uuid"`
	Validations map[string]StringOrList `json:"validations"`
}

// err converts a write response into an error. Adds must return a uuid.
func (w writeResponse) err(operation string) error {
	switch {
	case w.Result == "saved" && operation == opAddHostOverride && w.UUID == "":
		return &WriteError{Operation: operation, Result: "saved without uuid"}
	case w.Result == "saved":
		return nil
	default:
		return &WriteError{Operation: operation, Result: w.Result, Validations: w.Validations}
	}
}

type statusResponse struct {
	Status string `json:"status"`
}

// localData is one entry of diagnostics/listlocaldata.
//
//nolint:tagliatelle // OPNsense field names cannot be changed
type localData struct {
	Name   string `json:"name"`
	TTL    string `json:"ttl"`
	Type   string `json:"type"`
	RRType string `json:"rrtype"`
	Value  string `json:"value"`
}

type localDataResponse struct {
	Status string      `json:"status"`
	Data   []localData `json:"data"`
}

// stripTXTQuotes removes exactly one pair of surrounding double quotes.
// external-dns serialises registry labels quoted; OPNsense's template adds
// its own quotes when rendering local-data, so the stored value must be bare.
func stripTXTQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// restoreTXTQuotes is the inverse for values read back from the API.
func restoreTXTQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s
	}
	return `"` + s + `"`
}

// validateTXT applies the TXT rule from the design: one surrounding pair of
// quotes, a single character-string, printable ASCII, no inner quote or
// backslash, 1..255 bytes after stripping. It returns the bare value.
func validateTXT(target string) (string, error) {
	if len(target) < 2 || target[0] != '"' || target[len(target)-1] != '"' {
		return "", fmt.Errorf("%w: value must be one double-quoted string", ErrTXTInvalid)
	}
	bare := target[1 : len(target)-1]
	if bare == "" {
		return "", fmt.Errorf("%w: empty value", ErrTXTInvalid)
	}
	if len(bare) > maxTXTBytes {
		return "", fmt.Errorf("%w: %d bytes exceeds the %d-byte limit", ErrTXTInvalid, len(bare), maxTXTBytes)
	}
	for i := 0; i < len(bare); i++ {
		c := bare[i]
		if c < 0x20 || c > 0x7e {
			return "", fmt.Errorf("%w: byte %d is not printable ASCII", ErrTXTInvalid, i)
		}
		if c == '"' || c == '\\' {
			return "", fmt.Errorf("%w: quotes and backslashes are not allowed inside the value", ErrTXTInvalid)
		}
	}
	return bare, nil
}
