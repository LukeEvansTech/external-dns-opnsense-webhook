package opnsense

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestDTO_DecodeSearchPage(t *testing.T) {
	raw, err := os.ReadFile("testdata/search_page1.json")
	if err != nil {
		t.Fatal(err)
	}
	var page searchPage
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if page.Total != 3 || page.RowCount != 3 || page.Current != 1 || len(page.Rows) != 3 {
		t.Fatalf("page = %+v", page)
	}
	app := page.Rows[0]
	if bool(app.IsAlias) || app.Enabled != "1" || app.RR != "A" || app.Server != "192.0.2.10" {
		t.Errorf("row0 = %+v", app)
	}
	if len(app.Children) != 1 || !bool(app.Children[0].IsAlias) || app.Children[0].Hostname != "www" || app.Children[0].Domain != "" {
		t.Errorf("children = %+v", app.Children)
	}
	if page.Rows[2].Enabled != "0" || page.Rows[2].TTL != "300" {
		t.Errorf("row2 = %+v", page.Rows[2])
	}
}

func TestDTO_FlexBoolForms(t *testing.T) {
	cases := map[string]struct {
		want    bool
		wantErr bool
	}{
		`true`:    {true, false},
		`false`:   {false, false},
		`"1"`:     {true, false},
		`"0"`:     {false, false},
		`1`:       {true, false},
		`0`:       {false, false},
		`""`:      {false, false},
		`null`:    {false, false},
		`"maybe"`: {false, true},
		`"2"`:     {false, true},
	}
	for raw, tc := range cases {
		t.Run(raw, func(t *testing.T) {
			var b flexBool
			err := json.Unmarshal([]byte(raw), &b)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("%s: expected error, got %v", raw, b)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: %v", raw, err)
			}
			if bool(b) != tc.want {
				t.Errorf("%s = %v, want %v", raw, b, tc.want)
			}
		})
	}
}

func TestDTO_StringOrListForms(t *testing.T) {
	cases := map[string]struct {
		want    StringOrList
		wantErr bool
	}{
		`"x"`:       {StringOrList{"x"}, false},
		`["a","b"]`: {StringOrList{"a", "b"}, false},
		// encoding/json leaves a non-pointer destination untouched (and
		// returns no error) when the source is the JSON literal null, so a
		// null validations value decodes to a single empty-string entry
		// rather than an empty or nil list. Documented here as observed
		// behaviour of the string-then-list fallback, not a designed case.
		`null`: {StringOrList{""}, false},
		`5`:    {nil, true},
		`{}`:   {nil, true},
	}
	for raw, tc := range cases {
		t.Run(raw, func(t *testing.T) {
			var s StringOrList
			err := json.Unmarshal([]byte(raw), &s)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("%s: expected error, got %v", raw, s)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: %v", raw, err)
			}
			if len(s) != len(tc.want) {
				t.Fatalf("%s = %v, want %v", raw, s, tc.want)
			}
			for i := range s {
				if s[i] != tc.want[i] {
					t.Errorf("%s = %v, want %v", raw, s, tc.want)
				}
			}
		})
	}
}

func TestHostRow_TTLValue(t *testing.T) {
	cases := []struct {
		name string
		ttl  string
		want int64
	}{
		{"empty", "", 0},
		{"positive", "300", 300},
		{"non-numeric", "abc", 0},
		{"negative", "-5", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := hostRow{TTL: tc.ttl}
			if got := r.ttlValue(); got != tc.want {
				t.Errorf("ttlValue(%q) = %d, want %d", tc.ttl, got, tc.want)
			}
		})
	}
}

func TestHostRow_Target(t *testing.T) {
	cases := []struct {
		name string
		row  hostRow
		want string
	}{
		{"A record returns server", hostRow{RR: recordTypeA, Server: "192.0.2.10"}, "192.0.2.10"},
		{"TXT record quotes bare txtdata", hostRow{RR: recordTypeTXT, TXTData: "bare"}, `"bare"`},
		{"MX record joins prio and mx", hostRow{RR: recordTypeMX, MXPrio: "10", MX: "mail.example.com"}, "10 mail.example.com"},
		// MX is read-only knowledge for this provider (OPNsense has no
		// write path exercised for it in v1), so the "<prio> <mx>" format
		// with an empty prio producing a leading space is only
		// informational: it is never parsed back or round-tripped.
		{"MX record with empty prio", hostRow{RR: recordTypeMX, MXPrio: "", MX: "mx.example.com"}, " mx.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.row.target(); got != tc.want {
				t.Errorf("target() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHostRow_Enabled(t *testing.T) {
	cases := []struct {
		name    string
		enabled string
		want    bool
	}{
		{"one", "1", true},
		{"empty", "", false},
		{"zero", "0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := hostRow{Enabled: tc.enabled}
			if got := r.enabled(); got != tc.want {
				t.Errorf("enabled(%q) = %v, want %v", tc.enabled, got, tc.want)
			}
		})
	}
}

func TestDTO_WriteResponseValidations(t *testing.T) {
	raw, err := os.ReadFile("testdata/write_failed_array.json")
	if err != nil {
		t.Fatal(err)
	}
	var w writeResponse
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if w.Result != "failed" || len(w.Validations["host.txtdata"]) != 2 || len(w.Validations["host.domain"]) != 1 {
		t.Errorf("decoded = %+v", w)
	}
	werr := w.err("add_host_override")
	if werr == nil || !strings.Contains(werr.Error(), "host.txtdata") {
		t.Errorf("err = %v", werr)
	}
	ok := writeResponse{Result: "saved", UUID: "x"}
	if ok.err("add_host_override") != nil {
		t.Error("saved with uuid should be nil error")
	}
	noUUID := writeResponse{Result: "saved"}
	if noUUID.err("add_host_override") == nil {
		t.Error("saved without uuid on add must be an error")
	}
}

func TestTXT_QuoteRoundTrip(t *testing.T) {
	label := `heritage=external-dns,external-dns/owner=main,external-dns/resource=gateway-httproute/network/app`
	if got := stripTXTQuotes(`"` + label + `"`); got != label {
		t.Errorf("strip = %q", got)
	}
	if got := stripTXTQuotes(label); got != label {
		t.Errorf("strip unquoted = %q", got)
	}
	if got := restoreTXTQuotes(label); got != `"`+label+`"` {
		t.Errorf("restore = %q", got)
	}
	if got := restoreTXTQuotes(`"` + label + `"`); got != `"`+label+`"` {
		t.Errorf("restore already quoted = %q", got)
	}
}

func TestTXT_Validate(t *testing.T) {
	long := strings.Repeat("a", 255)
	cases := map[string]struct {
		in string
		ok bool
	}{
		"label":        {`"heritage=external-dns,external-dns/owner=main"`, true},
		"255 bytes":    {`"` + long + `"`, true},
		"256 bytes":    {`"` + long + `a"`, false},
		"inner quote":  {`"a"b"`, false},
		"backslash":    {`"a\b"`, false},
		"non-ascii":    {`"café"`, false},
		"control":      {"\"a\tb\"", false},
		"concatenated": {`"a" "b"`, false},
		"empty":        {`""`, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := validateTXT(tc.in)
			if tc.ok && err != nil {
				t.Errorf("rejected: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrTXTInvalid) {
				t.Errorf("accepted or wrong error: %v", err)
			}
		})
	}
}
