package fake

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func postJSON(t *testing.T, url string, body any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func TestFake_AddSearchDelete(t *testing.T) {
	s := New(t)
	id := s.AddRow(Row{Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.1"})
	s.AddAlias(id, "www", "")

	page := postJSON(t, s.URL()+"/api/unbound/settings/searchHostOverride",
		map[string]any{"current": 1, "rowCount": 10, "sort": map[string]string{"hostname": "asc"}})
	if page["total"].(float64) != 1 {
		t.Fatalf("total = %v", page["total"])
	}
	rows := page["rows"].([]any)
	row := rows[0].(map[string]any)
	if row["isAlias"] != false || len(row["_children"].([]any)) != 1 {
		t.Errorf("row = %v", row)
	}

	del := postJSON(t, s.URL()+"/api/unbound/settings/delHostOverride/"+id, map[string]any{})
	if del["result"] != "deleted" {
		t.Errorf("first delete = %v", del)
	}
	del = postJSON(t, s.URL()+"/api/unbound/settings/delHostOverride/"+id, map[string]any{})
	if del["result"] != "not found" {
		t.Errorf("second delete = %v", del)
	}
	if len(s.Rows()) != 0 || len(s.Aliases()) != 0 {
		t.Error("alias not cascaded")
	}
}

func TestFake_ValidationAndReconfigure(t *testing.T) {
	s := New(t)
	bad := postJSON(t, s.URL()+"/api/unbound/settings/addHostOverride",
		map[string]any{"host": map[string]string{
			"enabled": "1", "hostname": "t", "domain": "example.com", "rr": "TXT",
			"txtdata": string(make([]byte, 256)),
		}})
	if bad["result"] != "failed" {
		t.Fatalf("expected failed, got %v", bad)
	}
	if _, ok := bad["validations"].(map[string]any)["host.txtdata"]; !ok {
		t.Errorf("validations = %v", bad["validations"])
	}

	ok := postJSON(t, s.URL()+"/api/unbound/settings/addHostOverride",
		map[string]any{"host": map[string]string{
			"enabled": "1", "hostname": "app", "domain": "example.com", "rr": "A", "server": "192.0.2.1",
		}})
	if ok["result"] != "saved" || ok["uuid"] == "" {
		t.Fatalf("add = %v", ok)
	}
	if len(s.Served()) != 0 {
		t.Error("served before reconfigure")
	}
	rc := postJSON(t, s.URL()+"/api/unbound/service/reconfigure", map[string]any{})
	if rc["status"] != "ok" || len(s.Served()) != 1 || s.Reconfigures() != 1 {
		t.Errorf("reconfigure = %v served=%d", rc, len(s.Served()))
	}
	ld := postJSON(t, s.URL()+"/api/unbound/diagnostics/listlocaldata", map[string]any{})
	data := ld["data"].([]any)
	if len(data) != 1 || data[0].(map[string]any)["name"] != "app.example.com." {
		t.Errorf("listlocaldata = %v", data)
	}
}

func TestFake_FaultInjection(t *testing.T) {
	s := New(t)
	s.Inject(Fault{Op: OpReconfigure, Status: 500, Times: 1})
	resp, err := http.Post(s.URL()+"/api/unbound/service/reconfigure", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
	rc := postJSON(t, s.URL()+"/api/unbound/service/reconfigure", map[string]any{})
	if rc["status"] != "ok" {
		t.Errorf("second call should succeed: %v", rc)
	}

	s.Inject(Fault{Op: OpAddHostOverride, Status: 502, Times: 1, AfterCommit: true})
	addBody := `{"host":{"enabled":"1","hostname":"x","domain":"example.com","rr":"A","server":"192.0.2.9"}}`
	resp, err = http.Post(s.URL()+"/api/unbound/settings/addHostOverride", "application/json",
		bytes.NewReader([]byte(addBody)))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 502 || len(s.Rows()) != 1 {
		t.Errorf("after-commit fault: status=%d rows=%d", resp.StatusCode, len(s.Rows()))
	}
	if s.Hits(OpAddHostOverride) != 1 {
		t.Errorf("hits = %d", s.Hits(OpAddHostOverride))
	}
}

func TestFake_GetHostOverride(t *testing.T) {
	t.Run("known uuid", func(t *testing.T) {
		s := New(t)
		id := s.AddRow(Row{Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.1", Description: "d"})

		got := postJSON(t, s.URL()+"/api/unbound/settings/getHostOverride/"+id, map[string]any{})
		host, ok := got["host"].(map[string]any)
		if !ok {
			t.Fatalf("host = %v", got)
		}
		if host["uuid"] != id || host["hostname"] != "app" || host["domain"] != "example.com" ||
			host["rr"] != "A" || host["server"] != "192.0.2.1" || host["description"] != "d" {
			t.Errorf("host = %v", host)
		}
	})

	t.Run("unknown uuid", func(t *testing.T) {
		s := New(t)
		got := postJSON(t, s.URL()+"/api/unbound/settings/getHostOverride/does-not-exist", map[string]any{})
		if len(got) != 0 {
			t.Errorf("expected {}, got %v", got)
		}
	})
}

func TestFake_SetHostOverride(t *testing.T) {
	t.Run("changed fields land", func(t *testing.T) {
		s := New(t)
		id := s.AddRow(Row{Hostname: "old", Domain: "old.example.com", RR: "A", Server: "192.0.2.1"})

		got := postJSON(t, s.URL()+"/api/unbound/settings/setHostOverride/"+id, map[string]any{
			"host": map[string]string{
				"enabled": "0", "hostname": "new", "domain": "new.example.com", "rr": "MX",
				"server": "192.0.2.9", "txtdata": "v=spf1", "mx": "mail.example.com", "mxprio": "10",
				"ttl": "60",
			},
		})
		if got["result"] != "saved" {
			t.Fatalf("set = %v", got)
		}
		rows := s.Rows()
		if len(rows) != 1 {
			t.Fatalf("rows = %v", rows)
		}
		r := rows[0]
		switch {
		case r.Enabled != "0":
			t.Errorf("enabled = %q", r.Enabled)
		case r.Hostname != "new":
			t.Errorf("hostname = %q", r.Hostname)
		case r.Domain != "new.example.com":
			t.Errorf("domain = %q", r.Domain)
		case r.RR != "MX":
			t.Errorf("rr = %q", r.RR)
		case r.Server != "192.0.2.9":
			t.Errorf("server = %q", r.Server)
		case r.TXTData != "v=spf1":
			t.Errorf("txtdata = %q", r.TXTData)
		case r.MX != "mail.example.com":
			t.Errorf("mx = %q", r.MX)
		case r.MXPrio != "10":
			t.Errorf("mxprio = %q", r.MXPrio)
		case r.TTL != "60":
			t.Errorf("ttl = %q", r.TTL)
		}
	})

	t.Run("unknown uuid", func(t *testing.T) {
		s := New(t)
		got := postJSON(t, s.URL()+"/api/unbound/settings/setHostOverride/does-not-exist", map[string]any{
			"host": map[string]string{"hostname": "x", "domain": "example.com", "rr": "A", "server": "192.0.2.1"},
		})
		if got["result"] != "failed" {
			t.Errorf("set unknown = %v", got)
		}
	})

	t.Run("invalid payload leaves row unchanged", func(t *testing.T) {
		s := New(t)
		id := s.AddRow(Row{Hostname: "keep", Domain: "keep.example.com", RR: "A", Server: "192.0.2.5"})
		before := s.Rows()[0]

		got := postJSON(t, s.URL()+"/api/unbound/settings/setHostOverride/"+id, map[string]any{
			"host": map[string]string{"hostname": "", "domain": "keep.example.com", "rr": "A", "server": "192.0.2.5"},
		})
		if _, ok := got["validations"]; !ok {
			t.Errorf("expected validations, got %v", got)
		}
		after := s.Rows()[0]
		if after != before {
			t.Errorf("row changed: before=%+v after=%+v", before, after)
		}
	})
}

func TestFake_SortMultiKeyAndUUIDTieBreak(t *testing.T) {
	t.Run("tied fields order by uuid", func(t *testing.T) {
		s := New(t)
		s.AddRow(Row{
			UUID: "bbbbbbbb-0000-0000-0000-000000000000", Hostname: "same", Domain: "example.com",
			RR: "A", Server: "192.0.2.1",
		})
		s.AddRow(Row{
			UUID: "aaaaaaaa-0000-0000-0000-000000000000", Hostname: "same", Domain: "example.com",
			RR: "A", Server: "192.0.2.2",
		})

		page := postJSON(t, s.URL()+"/api/unbound/settings/searchHostOverride",
			map[string]any{"current": 1, "rowCount": 10, "sort": map[string]string{"hostname": "asc"}})
		rows := page["rows"].([]any)
		if len(rows) != 2 {
			t.Fatalf("rows = %v", rows)
		}
		first := rows[0].(map[string]any)["uuid"]
		second := rows[1].(map[string]any)["uuid"]
		if first != "aaaaaaaa-0000-0000-0000-000000000000" || second != "bbbbbbbb-0000-0000-0000-000000000000" {
			t.Errorf("order = %v, %v, want aaaa then bbbb", first, second)
		}
	})

	// map[string]string always marshals with its keys sorted, so a real
	// client's JSON body has "domain" before "hostname" no matter which
	// order the caller wrote them in. The fake doesn't rely on that (it
	// re-sorts the decoded field names itself via sort.Strings), but this
	// documents why "domain" wins as the primary key over "hostname" here
	// even though hostname is requested "desc": direction comes from the
	// first field alphabetically, which is "domain", not the first field
	// as written in the request.
	t.Run("alphabetically-first field name is primary", func(t *testing.T) {
		s := New(t)
		s.AddRow(Row{Hostname: "a", Domain: "b.example.com", RR: "A", Server: "192.0.2.1"})
		s.AddRow(Row{Hostname: "z", Domain: "a.example.com", RR: "A", Server: "192.0.2.2"})
		s.AddRow(Row{Hostname: "m", Domain: "a.example.com", RR: "A", Server: "192.0.2.3"})

		page := postJSON(t, s.URL()+"/api/unbound/settings/searchHostOverride",
			map[string]any{"current": 1, "rowCount": 10, "sort": map[string]string{"domain": "asc", "hostname": "desc"}})
		rows := page["rows"].([]any)
		if len(rows) != 3 {
			t.Fatalf("rows = %v", rows)
		}
		got := []string{
			rows[0].(map[string]any)["hostname"].(string),
			rows[1].(map[string]any)["hostname"].(string),
			rows[2].(map[string]any)["hostname"].(string),
		}
		want := []string{"m", "z", "a"}
		if got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
			t.Errorf("order = %v, want %v", got, want)
		}
	})
}

func TestFake_PagingBoundaries(t *testing.T) {
	s := New(t)
	for _, h := range []string{"a", "b", "c", "d", "e", "f"} {
		s.AddRow(Row{Hostname: h, Domain: "example.com", RR: "A", Server: "192.0.2.1"})
	}
	sortAsc := map[string]string{"hostname": "asc"}

	cases := []struct {
		name         string
		rowCount     int
		current      int
		wantHosts    []string
		wantRowCount int
	}{
		{"rowCount 0 returns all", 0, 1, []string{"a", "b", "c", "d", "e", "f"}, 6},
		{"rowCount -1 returns all", -1, 1, []string{"a", "b", "c", "d", "e", "f"}, 6},
		{"middle page", 2, 2, []string{"c", "d"}, 2},
		{"exact last page", 2, 3, []string{"e", "f"}, 2},
		{"one page past the end", 2, 4, nil, 0},
		{"current 0 treated as 1", 2, 0, []string{"a", "b"}, 2},
		{"current -1 treated as 1", 2, -1, []string{"a", "b"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page := postJSON(t, s.URL()+"/api/unbound/settings/searchHostOverride",
				map[string]any{"current": tc.current, "rowCount": tc.rowCount, "sort": sortAsc})
			if page["total"].(float64) != 6 {
				t.Fatalf("total = %v, want 6", page["total"])
			}
			if int(page["rowCount"].(float64)) != tc.wantRowCount {
				t.Errorf("rowCount = %v, want %d", page["rowCount"], tc.wantRowCount)
			}
			rows := page["rows"].([]any)
			if len(rows) != len(tc.wantHosts) {
				t.Fatalf("rows = %v, want %v", rows, tc.wantHosts)
			}
			for i, want := range tc.wantHosts {
				if got := rows[i].(map[string]any)["hostname"]; got != want {
					t.Errorf("rows[%d].hostname = %v, want %q", i, got, want)
				}
			}
		})
	}
}

func TestFake_FaultSkipCalls(t *testing.T) {
	s := New(t)
	s.Inject(Fault{Op: OpReconfigure, Status: http.StatusServiceUnavailable, Times: 1, SkipCalls: 2})

	wantStatus := []int{http.StatusOK, http.StatusOK, http.StatusServiceUnavailable, http.StatusOK}
	for i, want := range wantStatus {
		resp, err := http.Post(s.URL()+"/api/unbound/service/reconfigure", "application/json", bytes.NewReader([]byte("{}")))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("call %d: status = %d, want %d", i+1, resp.StatusCode, want)
		}
	}
	if s.Hits(OpReconfigure) != 4 {
		t.Errorf("hits = %d, want 4", s.Hits(OpReconfigure))
	}
}

func TestFake_FaultNotConsumedByInvalidRequest(t *testing.T) {
	s := New(t)
	s.Inject(Fault{Op: OpAddHostOverride, Status: http.StatusInternalServerError, Times: 1})

	bad := postJSON(t, s.URL()+"/api/unbound/settings/addHostOverride",
		map[string]any{"host": map[string]string{"hostname": "x", "domain": "example.com", "rr": "A"}})
	if bad["result"] != "failed" {
		t.Fatalf("expected validation failure, got %v", bad)
	}

	validBody := `{"host":{"hostname":"y","domain":"example.com","rr":"A","server":"192.0.2.1"}}`
	resp, err := http.Post(s.URL()+"/api/unbound/settings/addHostOverride", "application/json",
		bytes.NewReader([]byte(validBody)))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("valid add should fire the still-armed fault: status = %d", resp.StatusCode)
	}
}

func TestFake_SearchPhraseFilter(t *testing.T) {
	s := New(t)
	s.AddRow(Row{
		Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.1",
		Description: "production web server",
	})
	s.AddRow(Row{Hostname: "db", Domain: "example.com", RR: "A", Server: "192.0.2.2", Description: "database"})

	page := postJSON(t, s.URL()+"/api/unbound/settings/searchHostOverride",
		map[string]any{"current": 1, "rowCount": 10, "searchPhrase": "web server"})
	if page["total"].(float64) != 1 {
		t.Fatalf("total = %v", page["total"])
	}
	if page["rowCount"].(float64) != 1 {
		t.Fatalf("rowCount = %v", page["rowCount"])
	}
	rows := page["rows"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["hostname"] != "app" {
		t.Errorf("rows = %v", rows)
	}
}

func TestFake_ReconfigureDirect(t *testing.T) {
	s := New(t)
	s.AddRow(Row{Hostname: "app", Domain: "example.com", RR: "A", Server: "192.0.2.1"})

	if len(s.Served()) != 0 {
		t.Fatal("served before reconfigure")
	}
	s.Reconfigure()
	if len(s.Served()) != 1 || s.Reconfigures() != 1 {
		t.Fatalf("served = %v, reconfigures = %d", s.Served(), s.Reconfigures())
	}

	ld := postJSON(t, s.URL()+"/api/unbound/diagnostics/listlocaldata", map[string]any{})
	data := ld["data"].([]any)
	if len(data) != 1 || data[0].(map[string]any)["name"] != "app.example.com." {
		t.Errorf("listlocaldata = %v", data)
	}
}
