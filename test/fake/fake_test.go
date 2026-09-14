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
