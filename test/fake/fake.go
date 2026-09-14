// Package fake is an in-memory stand-in for the OPNsense Unbound settings API
// (26.7 shapes): a config table edited by the settings endpoints, a served
// table that only reconfigure publishes, OPNsense's sort and paging rules, and
// per-operation fault injection.
package fake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// Operation names used for hit counters and faults.
const (
	OpSearch          = "search_host_override"
	OpGet             = "get_host_override"
	OpAddHostOverride = "add_host_override"
	OpSet             = "set_host_override"
	OpDel             = "del_host_override"
	OpReconfigure     = "reconfigure"
	OpStatus          = "status"
	OpListLocalData   = "list_local_data"
)

// keyResult is the JSON field name OPNsense's write endpoints report their
// outcome under; resultFailed is its value on a validation failure. keyStatus
// is the JSON field name reconfigure/status/listlocaldata report under; it is
// spelled the same as OpStatus by coincidence — OpStatus names the operation
// for hit counters and faults, keyStatus names the response field.
const (
	keyResult    = "result"
	resultFailed = "failed"
	keyStatus    = "status"
)

// Row is a host override in the config table.
type Row struct {
	UUID        string
	Enabled     string
	Hostname    string
	Domain      string
	RR          string
	Server      string
	TXTData     string
	MX          string
	MXPrio      string
	TTL         string
	AddPTR      string
	Description string
}

// Alias is a host alias attached to a Row by UUID.
type Alias struct {
	UUID        string
	Host        string
	Enabled     string
	Hostname    string
	Domain      string
	Description string
}

// Fault makes the next Times calls to Op answer Status. With AfterCommit the
// write is applied first, simulating a committed write whose response is lost.
// SkipCalls lets that many calls to Op through before the fault fires, so a
// test can target the Nth call of a phase-ordered apply.
//
// A fault fires only on a call that would otherwise succeed; an invalid
// payload or unknown uuid answers normally and leaves the fault armed.
type Fault struct {
	Op          string
	Status      int
	Times       int
	AfterCommit bool
	SkipCalls   int
}

// Served is one rendered local-data entry, as listlocaldata reports it.
type Served struct {
	Name   string `json:"name"`
	TTL    string `json:"ttl"`
	Type   string `json:"type"`
	RRType string `json:"rrtype"`
	Value  string `json:"value"`
}

// Server is the fake.
type Server struct {
	mu           sync.Mutex
	rows         []*Row
	aliases      []*Alias
	served       []Served
	faults       []*Fault
	hits         map[string]int
	reconfigures int
	srv          *httptest.Server
}

// New starts a fake bound to the test's lifetime.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{hits: map[string]int{}}
	s.srv = httptest.NewServer(s.Handler())
	t.Cleanup(s.srv.Close)
	return s
}

// URL is the base URL (scheme and host).
func (s *Server) URL() string { return s.srv.URL }

// AddRow inserts a row directly (a hand-made row). Empty Enabled means "1".
// Empty AddPTR defaults to "0" here, deliberately unlike the API handlers
// (handleAdd/handleSet), which default it to "1" like the real model — a
// hand-made row is assumed to state what it wants, not to come from a client
// that omitted the field.
func (s *Server) AddRow(r Row) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.UUID == "" {
		r.UUID = uuid.NewString()
	}
	if r.Enabled == "" {
		r.Enabled = "1"
	}
	if r.RR == "" {
		r.RR = "A"
	}
	if r.AddPTR == "" {
		r.AddPTR = "0"
	}
	rr := r
	s.rows = append(s.rows, &rr)
	return rr.UUID
}

// AddAlias attaches a hand-made alias to a row.
func (s *Server) AddAlias(host, hostname, domain string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := &Alias{UUID: uuid.NewString(), Host: host, Enabled: "1", Hostname: hostname, Domain: domain}
	s.aliases = append(s.aliases, a)
	return a.UUID
}

// Rows returns a copy of the config table.
func (s *Server) Rows() []Row {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Row, 0, len(s.rows))
	for _, r := range s.rows {
		out = append(out, *r)
	}
	return out
}

// Aliases returns a copy of the alias table.
func (s *Server) Aliases() []Alias {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Alias, 0, len(s.aliases))
	for _, a := range s.aliases {
		out = append(out, *a)
	}
	return out
}

// Served returns what the last reconfigure published.
func (s *Server) Served() []Served {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Served(nil), s.served...)
}

// Reconfigures counts successful reconfigure calls.
func (s *Server) Reconfigures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reconfigures
}

// Hits counts calls to an operation, faults included.
func (s *Server) Hits(op string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[op]
}

// Inject arms a fault.
func (s *Server) Inject(f Fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ff := f
	s.faults = append(s.faults, &ff)
}

// Reconfigure publishes the config table as if the API had been called.
func (s *Server) Reconfigure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publishLocked()
}

// takeFault returns the armed fault for op, decrementing it. Caller holds mu.
func (s *Server) takeFault(op string) *Fault {
	for i, f := range s.faults {
		if f.Op != op || f.Times <= 0 {
			continue
		}
		if f.SkipCalls > 0 {
			f.SkipCalls--
			return nil
		}
		f.Times--
		if f.Times == 0 {
			s.faults = append(s.faults[:i], s.faults[i+1:]...)
		}
		return f
	}
	return nil
}

// Handler routes the API paths the provider uses.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/unbound/settings/searchHostOverride", s.handleSearch)
	mux.HandleFunc("/api/unbound/settings/getHostOverride/", s.handleGet)
	mux.HandleFunc("/api/unbound/settings/addHostOverride", s.handleAdd)
	mux.HandleFunc("/api/unbound/settings/setHostOverride/", s.handleSet)
	mux.HandleFunc("/api/unbound/settings/delHostOverride/", s.handleDel)
	mux.HandleFunc("/api/unbound/service/reconfigure", s.handleReconfigure)
	mux.HandleFunc("/api/unbound/service/status", s.handleStatus)
	mux.HandleFunc("/api/unbound/diagnostics/listlocaldata", s.handleListLocalData)
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// rowJSON renders a row in the search/get shape, children included.
func (s *Server) rowJSON(r *Row, withChildren bool) map[string]any {
	m := map[string]any{
		"uuid": r.UUID, "enabled": r.Enabled, "hostname": r.Hostname, "domain": r.Domain,
		"rr": r.RR, "server": r.Server, "txtdata": r.TXTData, "mx": r.MX, "mxprio": r.MXPrio,
		"ttl": r.TTL, "addptr": r.AddPTR, "description": r.Description, "isAlias": false,
	}
	if !withChildren {
		return m
	}
	for _, a := range s.aliases {
		if a.Host != r.UUID {
			continue
		}
		c := map[string]any{}
		for k, v := range m {
			c[k] = v
		}
		c["uuid"], c["isAlias"] = a.UUID, true
		c["enabled"], c["hostname"], c["domain"], c["description"] = a.Enabled, a.Hostname, a.Domain, a.Description
		if m["_children"] == nil {
			m["_children"] = []map[string]any{}
		}
		m["_children"] = append(m["_children"].([]map[string]any), c)
	}
	return m
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits[OpSearch]++
	if f := s.takeFault(OpSearch); f != nil {
		http.Error(w, "injected", f.Status)
		return
	}
	var req struct {
		Current      int               `json:"current"`
		RowCount     int               `json:"rowCount"`
		Sort         map[string]string `json:"sort"`
		SearchPhrase string            `json:"searchPhrase"`
	}
	req.RowCount = -1
	req.Current = 1
	if r.Method == http.MethodPost {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	if req.Current < 1 {
		req.Current = 1
	}
	// Sort: OPNsense builds one key from every sort field (padded to 30
	// chars) and appends the node uuid, then ksort()s. Direction comes from
	// the first key only. Reproduce that so tests exercise the real order.
	// Padding here is always left-aligned (%-30s); OPNsense right-aligns
	// numeric fields when building this key, so a numeric field's sort order
	// (ttl is the only one exposed) is not faithfully modelled here.
	fields := make([]string, 0, len(req.Sort))
	for k := range req.Sort {
		fields = append(fields, k)
	}
	sort.Strings(fields)
	desc := len(fields) > 0 && strings.EqualFold(req.Sort[fields[0]], "desc")
	keyOf := func(r *Row) string {
		var b strings.Builder
		for _, f := range fields {
			fmt.Fprintf(&b, "%-30s,", fieldValue(r, f))
		}
		b.WriteString(r.UUID)
		return b.String()
	}
	rows := make([]*Row, 0, len(s.rows))
	phrase := strings.ToLower(req.SearchPhrase)
	for _, row := range s.rows {
		if phrase == "" || strings.Contains(searchable(row), phrase) {
			rows = append(rows, row)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if desc {
			return keyOf(rows[i]) > keyOf(rows[j])
		}
		return keyOf(rows[i]) < keyOf(rows[j])
	})
	total := len(rows)
	if req.RowCount > 0 {
		start := (req.Current - 1) * req.RowCount
		if start > len(rows) {
			start = len(rows)
		}
		end := start + req.RowCount
		if end > len(rows) {
			end = len(rows)
		}
		rows = rows[start:end]
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, s.rowJSON(row, true))
	}
	writeJSON(w, map[string]any{"rows": out, "rowCount": len(out), "total": total, "current": req.Current})
}

// searchable is the lowercased text searchPhrase matches a substring against:
// hostname, domain, server, description and txtdata.
func searchable(r *Row) string {
	return strings.ToLower(r.Hostname + " " + r.Domain + " " + r.Server + " " + r.Description + " " + r.TXTData)
}

func fieldValue(r *Row, f string) string {
	switch f {
	case "hostname":
		return r.Hostname
	case "domain":
		return r.Domain
	case "rr":
		return r.RR
	case "server":
		return r.Server
	case "description":
		return r.Description
	case "ttl":
		return r.TTL
	}
	return ""
}

func lastSegment(p string) string { return p[strings.LastIndex(p, "/")+1:] }

func (s *Server) find(id string) (int, *Row) {
	for i, r := range s.rows {
		if r.UUID == id {
			return i, r
		}
	}
	return -1, nil
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits[OpGet]++
	if f := s.takeFault(OpGet); f != nil {
		http.Error(w, "injected", f.Status)
		return
	}
	_, row := s.find(lastSegment(r.URL.Path))
	if row == nil {
		writeJSON(w, map[string]any{})
		return
	}
	writeJSON(w, map[string]any{"host": s.rowJSON(row, false)})
}

type hostBody struct {
	Host map[string]string `json:"host"`
}

func validate(h map[string]string) map[string]string {
	v := map[string]string{}
	if h["hostname"] == "" {
		v["host.hostname"] = "A valid hostname must be specified."
	}
	if h["domain"] == "" {
		v["host.domain"] = "A valid domain must be specified."
	}
	switch h["rr"] {
	case "A", "AAAA":
		if h["server"] == "" {
			v["host.server"] = "The field IP address is required."
		}
	case "TXT":
		if h["txtdata"] == "" {
			v["host.txtdata"] = "The field TXT data is required."
		} else if len(h["txtdata"]) > 255 {
			v["host.txtdata"] = "Text may not exceed 255 characters."
		}
	case "MX":
	default:
		v["host.rr"] = "Option not in list."
	}
	return v
}

func (s *Server) handleAdd(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits[OpAddHostOverride]++
	var b hostBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Host == nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if v := validate(b.Host); len(v) > 0 {
		writeJSON(w, map[string]any{keyResult: resultFailed, "validations": v})
		return
	}
	f := s.takeFault(OpAddHostOverride)
	if f != nil && !f.AfterCommit {
		http.Error(w, "injected", f.Status)
		return
	}
	row := &Row{
		UUID: uuid.NewString(), Enabled: orDefault(b.Host["enabled"], "1"),
		Hostname: b.Host["hostname"], Domain: b.Host["domain"],
		RR: b.Host["rr"], Server: b.Host["server"], TXTData: b.Host["txtdata"],
		MX: b.Host["mx"], MXPrio: b.Host["mxprio"], TTL: b.Host["ttl"],
		AddPTR: orDefault(b.Host["addptr"], "1"), Description: b.Host["description"],
	}
	s.rows = append(s.rows, row)
	if f != nil {
		http.Error(w, "injected after commit", f.Status)
		return
	}
	writeJSON(w, map[string]any{keyResult: "saved", "uuid": row.UUID})
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func (s *Server) handleSet(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits[OpSet]++
	var b hostBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Host == nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	_, row := s.find(lastSegment(r.URL.Path))
	if row == nil {
		writeJSON(w, map[string]any{keyResult: resultFailed})
		return
	}
	if v := validate(b.Host); len(v) > 0 {
		writeJSON(w, map[string]any{keyResult: resultFailed, "validations": v})
		return
	}
	f := s.takeFault(OpSet)
	if f != nil && !f.AfterCommit {
		http.Error(w, "injected", f.Status)
		return
	}
	row.Enabled = orDefault(b.Host["enabled"], "1")
	row.Hostname, row.Domain, row.RR = b.Host["hostname"], b.Host["domain"], b.Host["rr"]
	row.Server, row.TXTData, row.MX, row.MXPrio = b.Host["server"], b.Host["txtdata"], b.Host["mx"], b.Host["mxprio"]
	row.TTL, row.AddPTR, row.Description = b.Host["ttl"], orDefault(b.Host["addptr"], "1"), b.Host["description"]
	if f != nil {
		http.Error(w, "injected after commit", f.Status)
		return
	}
	writeJSON(w, map[string]any{keyResult: "saved"})
}

func (s *Server) handleDel(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits[OpDel]++
	id := lastSegment(r.URL.Path)
	i, row := s.find(id)
	if row == nil {
		writeJSON(w, map[string]any{keyResult: "not found"})
		return
	}
	f := s.takeFault(OpDel)
	if f != nil && !f.AfterCommit {
		http.Error(w, "injected", f.Status)
		return
	}
	s.rows = append(s.rows[:i], s.rows[i+1:]...)
	kept := s.aliases[:0]
	for _, a := range s.aliases {
		if a.Host != id {
			kept = append(kept, a)
		}
	}
	s.aliases = kept
	if f != nil {
		http.Error(w, "injected after commit", f.Status)
		return
	}
	writeJSON(w, map[string]any{keyResult: "deleted"})
}

func (s *Server) handleReconfigure(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits[OpReconfigure]++
	if f := s.takeFault(OpReconfigure); f != nil {
		http.Error(w, "injected", f.Status)
		return
	}
	s.publishLocked()
	writeJSON(w, map[string]any{keyStatus: "ok"})
}

// hostDomain is one name a row (or one of its aliases) is served under.
type hostDomain struct{ host, domain string }

// servedName renders the FQDN unbound_add_host_entries serves a host+domain
// pair under. A blank host is a domain-apex override (OPNsense allows leaving
// the host field blank to override the domain itself), so the name is just
// "domain." — not ".domain." with a leading dot.
func servedName(host, domain string) string {
	if host == "" {
		return domain + "."
	}
	return host + "." + domain + "."
}

// publishLocked renders the config table the way unbound_add_host_entries
// does: each enabled row at its own name, plus a parent-type copy at each
// enabled alias name; TXT values wrapped in quotes.
func (s *Server) publishLocked() {
	s.reconfigures++
	s.served = s.served[:0]
	for _, row := range s.rows {
		if row.Enabled == "0" {
			continue
		}
		names := []hostDomain{{row.Hostname, row.Domain}}
		for _, a := range s.aliases {
			if a.Host == row.UUID && a.Enabled != "0" {
				names = append(names, hostDomain{orDefault(a.Hostname, row.Hostname), orDefault(a.Domain, row.Domain)})
			}
		}
		for _, n := range names {
			e := Served{Name: servedName(n.host, n.domain), TTL: orDefault(row.TTL, "3600"), Type: "IN", RRType: row.RR}
			switch row.RR {
			case "TXT":
				e.Value = `"` + row.TXTData + `"`
			case "MX":
				e.Value = row.MXPrio + " " + row.MX
			default:
				e.Value = row.Server
			}
			s.served = append(s.served, e)
		}
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits[OpStatus]++
	if f := s.takeFault(OpStatus); f != nil {
		http.Error(w, "injected", f.Status)
		return
	}
	writeJSON(w, map[string]any{keyStatus: "running"})
}

func (s *Server) handleListLocalData(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits[OpListLocalData]++
	if f := s.takeFault(OpListLocalData); f != nil {
		http.Error(w, "injected", f.Status)
		return
	}
	writeJSON(w, map[string]any{keyStatus: "ok", "data": append([]Served{}, s.served...)})
}
