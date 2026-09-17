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
