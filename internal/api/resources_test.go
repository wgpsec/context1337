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

func TestListResourcesAppliesFullTextQuery(t *testing.T) {
	router := setupTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/resources?type=skill&q=definitely-not-present", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Total        int              `json:"total"`
		Items        []map[string]any `json:"items"`
		QueryApplied bool             `json:"query_applied"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !body.QueryApplied {
		t.Fatal("query_applied = false, want true")
	}
	if body.Total != 0 || len(body.Items) != 0 {
		t.Fatalf("non-matching query returned total=%d items=%d", body.Total, len(body.Items))
	}
}

func TestListResourcesQueryIncludesDisabledResourcesForManagement(t *testing.T) {
	db, err := storage.OpenDB(filepath.Join(t.TempDir(), "resources.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := search.InsertResource(db, search.Resource{
		Type: "skill", Name: "disabled-search-target", Source: "custom",
		Description: "management-only knowledge",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE resources SET enabled = 0 WHERE name = ?", "disabled-search-target"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/resources?type=skill&q=management", nil)
	rec := httptest.NewRecorder()
	NewRouter(db, t.TempDir(), "", nil).ServeHTTP(rec, req)

	var body struct {
		Total int `json:"total"`
		Items []struct {
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
		} `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 1 || len(body.Items) != 1 {
		t.Fatalf("disabled management match missing: total=%d items=%d", body.Total, len(body.Items))
	}
	if body.Items[0].Name != "disabled-search-target" || body.Items[0].Enabled {
		t.Fatalf("unexpected item: %+v", body.Items[0])
	}

	enabledReq := httptest.NewRequest(http.MethodGet, "/api/resources?type=skill&q=management&enabled=true", nil)
	enabledRec := httptest.NewRecorder()
	NewRouter(db, t.TempDir(), "", nil).ServeHTTP(enabledRec, enabledReq)
	var enabledBody struct {
		Total int `json:"total"`
	}
	if err := json.NewDecoder(enabledRec.Body).Decode(&enabledBody); err != nil {
		t.Fatal(err)
	}
	if enabledBody.Total != 0 {
		t.Fatalf("disabled resource leaked through enabled=true search: total=%d", enabledBody.Total)
	}
}
