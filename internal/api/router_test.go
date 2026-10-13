package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wgpsec/context1337/internal/search"
	"github.com/wgpsec/context1337/internal/storage"
	"github.com/wgpsec/context1337/internal/usage"
)

func setupTestRouter(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	search.InsertResource(db, search.Resource{
		Type: "skill", Name: "test-skill", Source: "builtin",
		FilePath: "skills/test/SKILL.md", Category: "exploit",
		Description: "Test skill",
	})

	return NewRouter(db, dir, nil, nil, "")
}

func TestUsageEndpointUsesMCPAPIKey(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.OpenDB(filepath.Join(dir, "usage.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	collector := usage.NewCollector()
	collector.RecordTool("search_security", true, 5*time.Millisecond, 128)
	router := NewRouter(db, dir, testAuthStore(t, "mcp-api-key"), nil, "", UsageEndpoint{Collector: collector})

	for _, token := range []string{"", "wrong-token"} {
		req := httptest.NewRequest(http.MethodGet, "/api/usage", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("token %q: status = %d, want 401", token, recorder.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/usage", nil)
	req.Header.Set("Authorization", "Bearer mcp-api-key")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	var snapshot usage.Snapshot
	if err := json.NewDecoder(recorder.Body).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Tools.CallsTotal != 1 {
		t.Errorf("tool calls = %d, want 1", snapshot.Tools.CallsTotal)
	}
}

func TestUsageEndpointIsDisabledWithoutMCPAPIKey(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.OpenDB(filepath.Join(dir, "usage-disabled.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	router := NewRouter(db, dir, nil, nil, "", UsageEndpoint{
		Collector: usage.NewCollector(),
	})
	req := httptest.NewRequest(http.MethodGet, "/api/usage", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when MCP API key is empty", recorder.Code)
	}
}

func TestHealthEndpoint(t *testing.T) {
	router := setupTestRouter(t)
	req := httptest.NewRequest("GET", "/api/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var body map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	// setupTestRouter inserts 1 skill
	if body["total_resources"] != float64(1) {
		t.Errorf("total_resources = %v, want 1", body["total_resources"])
	}
	if body["skills"] != float64(1) {
		t.Errorf("skills = %v, want 1", body["skills"])
	}
	// types with 0 resources should be absent
	for _, key := range []string{"vulns", "dicts", "payloads"} {
		if _, ok := body[key]; ok {
			t.Errorf("unexpected key %q in response (no resources of that type)", key)
		}
	}
}

func TestStatsEndpoint(t *testing.T) {
	router := setupTestRouter(t)
	req := httptest.NewRequest("GET", "/api/stats", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	// The historical response carries no `group` key. Grouping support must not
	// leak into it, or old clients start seeing a field they cannot interpret.
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["group"]; ok {
		t.Errorf("ungrouped response unexpectedly carries a group key: %s", rec.Body.String())
	}
}

func TestStatsGroupCategoryBucketsByTypeAndCategory(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.OpenDB(filepath.Join(dir, "stats.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	for _, resource := range []search.Resource{
		{Type: "skill", Name: "a", Source: "builtin", FilePath: "skills/a/SKILL.md", Category: "exploit"},
		{Type: "skill", Name: "b", Source: "builtin", FilePath: "skills/b/SKILL.md", Category: "exploit"},
		{Type: "skill", Name: "c", Source: "builtin", FilePath: "skills/c/SKILL.md", Category: "tool"},
		{Type: "skill", Name: "d", Source: "builtin", FilePath: "skills/d/SKILL.md", Category: ""},
		{Type: "vuln", Name: "e", Source: "builtin", FilePath: "vulns/e.md", Category: "web"},
	} {
		search.InsertResource(db, resource)
	}
	router := NewRouter(db, dir, nil, nil, "")

	req := httptest.NewRequest("GET", "/api/stats?group=category", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Group string `json:"group"`
		Stats []struct {
			Type     string `json:"type"`
			Category string `json:"category"`
			Count    int    `json:"count"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Group != "category" {
		t.Errorf("group = %q, want category", payload.Group)
	}

	buckets := map[string]int{}
	for _, stat := range payload.Stats {
		buckets[stat.Type+"/"+stat.Category] = stat.Count
	}
	// The empty category is a real bucket: dropping it would make the facet
	// counts sum to less than the type total.
	want := map[string]int{"skill/exploit": 2, "skill/tool": 1, "skill/": 1, "vuln/web": 1}
	if len(buckets) != len(want) {
		t.Fatalf("buckets = %v, want %v", buckets, want)
	}
	for key, count := range want {
		if buckets[key] != count {
			t.Errorf("bucket %q = %d, want %d", key, buckets[key], count)
		}
	}

	// Facet counts must sum back to the per-type totals the ungrouped view and
	// /api/health report.
	grouped := httptest.NewRequest("GET", "/api/stats", nil)
	groupedRec := httptest.NewRecorder()
	router.ServeHTTP(groupedRec, grouped)
	var ungrouped struct {
		Stats []struct {
			Type  string `json:"type"`
			Count int    `json:"count"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(groupedRec.Body.Bytes(), &ungrouped); err != nil {
		t.Fatalf("decode ungrouped: %v", err)
	}
	totals := map[string]int{}
	facetTotals := map[string]int{}
	for _, stat := range ungrouped.Stats {
		totals[stat.Type] += stat.Count
	}
	for _, stat := range payload.Stats {
		facetTotals[stat.Type] += stat.Count
	}
	if len(totals) != len(facetTotals) {
		t.Fatalf("type totals = %v, facet totals = %v", totals, facetTotals)
	}
	for typ, total := range totals {
		if facetTotals[typ] != total {
			t.Errorf("type %q: facet sum = %d, want %d", typ, facetTotals[typ], total)
		}
	}
}

func TestStatsRejectsUnknownGroup(t *testing.T) {
	router := setupTestRouter(t)
	req := httptest.NewRequest("GET", "/api/stats?group=source", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestStatsEnabledAllIncludesDisabledResources(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.OpenDB(filepath.Join(dir, "enabled.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	search.InsertResource(db, search.Resource{
		Type: "skill", Name: "kept", Source: "builtin",
		FilePath: "skills/kept/SKILL.md", Category: "exploit",
	})
	search.InsertResource(db, search.Resource{
		Type: "skill", Name: "off", Source: "builtin",
		FilePath: "skills/off/SKILL.md", Category: "exploit",
	})
	if _, err := db.Exec("UPDATE resources SET enabled = 0 WHERE name = 'off'"); err != nil {
		t.Fatal(err)
	}
	router := NewRouter(db, dir, nil, nil, "")

	countFor := func(url string) int {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest("GET", url, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200; body=%s", url, rec.Code, rec.Body.String())
		}
		var payload struct {
			Stats []struct {
				Count int `json:"count"`
			} `json:"stats"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("%s: decode: %v", url, err)
		}
		total := 0
		for _, stat := range payload.Stats {
			total += stat.Count
		}
		return total
	}

	if got := countFor("/api/stats?group=category"); got != 1 {
		t.Errorf("default enabled-only count = %d, want 1", got)
	}
	if got := countFor("/api/stats?group=category&enabled=all"); got != 2 {
		t.Errorf("enabled=all count = %d, want 2", got)
	}
	if got := countFor("/api/stats?group=category&enabled=false"); got != 1 {
		t.Errorf("enabled=false count = %d, want 1", got)
	}
}

func TestLivenessEndpoint(t *testing.T) {
	router := setupTestRouter(t)
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := strings.TrimSpace(rec.Body.String())
	if body != "OK" {
		t.Errorf("body = %q, want \"OK\"", body)
	}
}
