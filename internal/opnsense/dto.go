package opnsense

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
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

// optionField decodes a select field in either of the two shapes the API uses
// for the same value. searchHostOverride flattens it to the selected key
// ("A") and puts the display text in a sibling "%rr" field; getHostOverride
// expands the whole option set instead — {"A":{"value":"A (IPv4 address)",
// "selected":1},"AAAA":{...},...} — and leaves the reader to find the
// selected key. A row decoded from either endpoint must come out the same, so
// this resolves the expanded form back to the bare key.
type optionField string

// option is one entry of an expanded option set. Only the flag matters here;
// "value" is display text for the UI. getHostOverride sends the flag as a
// number, but the model layer spells booleans several ways elsewhere, so it is
// read through flexBool rather than as an int.
type option struct {
	Selected flexBool `json:"selected"`
}

func (o *optionField) UnmarshalJSON(data []byte) error {
	var flat string
	if err := json.Unmarshal(data, &flat); err == nil {
		*o = optionField(flat)
		return nil
	}
	var set map[string]option
	if err := json.Unmarshal(data, &set); err != nil {
		return fmt.Errorf("opnsense: option field is neither a key nor an option set: %w", err)
	}
	selected := make([]string, 0, 1)
	for key, opt := range set {
		if bool(opt.Selected) {
			selected = append(selected, key)
		}
	}
	// Sorted so the message is the same on every run: map iteration is not.
	sort.Strings(selected)
	switch len(selected) {
	case 1:
		*o = optionField(selected[0])
		return nil
	case 0:
		return errors.New("opnsense: option field has no selected value")
	default:
		return fmt.Errorf("opnsense: option field has %d selected values: %s", len(selected), strings.Join(selected, ", "))
	}
}

// hostRow is one row of searchHostOverride (26.1+ tree view) or the body of
// getHostOverride. Alias children carry the parent's rr/server/ttl and their
// own hostname/domain/description; an empty hostname or domain on a child
// means "inherit from the parent" (unbound.inc).
//
// The two endpoints do not agree on how a select field is rendered, so RR is
// decoded through optionField in UnmarshalJSON below and kept here as the bare
// key every other package compares against.
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

// UnmarshalJSON decodes rr from either endpoint's spelling while leaving RR a
// plain string for every caller. The shim embeds a method-free copy of hostRow
// — so this method cannot recurse into itself — and shadows rr with a field
// one level shallower, which encoding/json prefers, so the option decoding
// runs and the embedded string field is left alone. Children decode through
// this same method, so an expanded alias row resolves too.
func (r *hostRow) UnmarshalJSON(data []byte) error {
	type plain hostRow
	var shim struct {
		plain
		RR optionField `json:"rr"`
	}
	if err := json.Unmarshal(data, &shim); err != nil {
		return err
	}
	*r = hostRow(shim.plain)
	r.RR = string(shim.RR)
	return nil
}

func (r hostRow) enabled() bool { return r.Enabled != "0" && r.Enabled != "" }

// ttlValue returns the row's TTL or 0 when unset.
func (r hostRow) ttlValue() int64 { return parseTTL(r.TTL) }

// parseTTL reads a ttl field as the model stores it: empty, unparsable and
// negative all mean unset.
func parseTTL(s string) int64 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
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

// target is the value the write carries: txtdata for TXT, server otherwise.
func (f hostFields) target() string {
	if f.RR == recordTypeTXT {
		return f.TXTData
	}
	return f.Server
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
