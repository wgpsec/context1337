package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/wgpsec/context1337/internal/search"
	"github.com/wgpsec/context1337/internal/storage"
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

	return NewRouter(db, dir, "", nil)
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
