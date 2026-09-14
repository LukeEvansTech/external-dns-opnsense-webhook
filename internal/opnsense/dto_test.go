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
	for raw, want := range map[string]bool{`true`: true, `false`: false, `"1"`: true, `"0"`: false, `1`: true, `0`: false, `""`: false} {
		var b flexBool
		if err := json.Unmarshal([]byte(raw), &b); err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		if bool(b) != want {
			t.Errorf("%s = %v, want %v", raw, b, want)
		}
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
