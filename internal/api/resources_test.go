package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestListResourcesUsesVersionedCanonicalSearchOrdering(t *testing.T) {
	db, err := storage.OpenDB(filepath.Join(t.TempDir(), "resources.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	for _, resource := range []search.Resource{
		{
			Type: "skill", Name: "jwt-attack-methodology", Source: "builtin",
			Description: "JWT 算法混淆方法论", Tags: "jwt,算法混淆",
		},
		{
			Type: "skill", Name: "generic-auth-audit", Source: "builtin",
			Description: "JWT algorithm confusion audit", Tags: "jwt,algorithm,confusion",
		},
	} {
		if err := search.InsertResource(db, resource); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/resources?type=skill&q=JWT+algorithm+confusion&enabled=true", nil)
	rec := httptest.NewRecorder()
	NewRouter(db, t.TempDir(), nil, nil, "").ServeHTTP(rec, req)

	var body struct {
		SearchVersion string `json:"search_version"`
		Items         []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.SearchVersion != search.SearchContractVersion {
		t.Fatalf("search_version = %q, want %q", body.SearchVersion, search.SearchContractVersion)
	}
	if len(body.Items) == 0 || body.Items[0].Name != "jwt-attack-methodology" {
		t.Fatalf("top result = %+v, want jwt-attack-methodology", body.Items)
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
	NewRouter(db, t.TempDir(), nil, nil, "").ServeHTTP(rec, req)

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
	NewRouter(db, t.TempDir(), nil, nil, "").ServeHTTP(enabledRec, enabledReq)
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

func TestListResourcesAppliesPinyinFallbackForUnknownHanContext(t *testing.T) {
	db, err := storage.OpenDB(filepath.Join(t.TempDir(), "resources.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := search.InsertResource(db, search.Resource{
		Type: "vuln", Name: "CNVD-2021-32799", Source: "nuclei",
		Tags:        "cnvd2021,cnvd,360,xintianqing,sqli,vuln",
		Description: "Tianqing Terminal Security Management System SQL injection",
		Metadata:    `{"severity":"HIGH"}`,
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/resources?type=vuln&q="+url.QueryEscape("天擎 360 sqli"), nil)
	rec := httptest.NewRecorder()
	NewRouter(db, t.TempDir(), nil, nil, "").ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Total int `json:"total"`
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
		Resolution *struct {
			Mode             string `json:"mode"`
			OriginalQuery    string `json:"original_query"`
			EffectiveQuery   string `json:"effective_query"`
			Transliterations []struct {
				From string `json:"from"`
				To   string `json:"to"`
			} `json:"transliterations"`
		} `json:"resolution"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 1 || len(body.Items) != 1 || body.Items[0].Name != "CNVD-2021-32799" {
		t.Fatalf("REST pinyin fallback missed resource: %+v", body)
	}
	if body.Resolution == nil || body.Resolution.Mode != "transliterated" ||
		body.Resolution.OriginalQuery != "天擎 360 sqli" ||
		body.Resolution.EffectiveQuery != "tianqing 360 sqli" {
		t.Fatalf("resolution = %+v, want transliterated tianqing mapping", body.Resolution)
	}
	if len(body.Resolution.Transliterations) != 1 ||
		body.Resolution.Transliterations[0].From != "天擎" ||
		body.Resolution.Transliterations[0].To != "tianqing" {
		t.Fatalf("transliterations = %+v", body.Resolution.Transliterations)
	}
}

func TestListResourcesExactChineseMatchOmitsFallbackResolution(t *testing.T) {
	db, err := storage.OpenDB(filepath.Join(t.TempDir(), "resources.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := search.InsertResource(db, search.Resource{
		Type: "vuln", Name: "exact-chinese-product", Source: "nuclei",
		Tags: "天擎,sqli", Description: "天擎 SQL 注入", Metadata: `{"severity":"HIGH"}`,
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/resources?type=vuln&q="+url.QueryEscape("天擎 sqli"), nil)
	rec := httptest.NewRecorder()
	NewRouter(db, t.TempDir(), nil, nil, "").ServeHTTP(rec, req)

	var body struct {
		Total int `json:"total"`
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
		Resolution *struct {
			Mode string `json:"mode"`
		} `json:"resolution"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 1 || len(body.Items) != 1 || body.Items[0].Name != "exact-chinese-product" {
		t.Fatalf("exact match missing: %+v", body)
	}
	if body.Resolution != nil {
		t.Fatalf("exact match advertised fallback: %+v", body.Resolution)
	}
}

func TestListResourcesOrdersByIDDescending(t *testing.T) {
	db, err := storage.OpenDB(filepath.Join(t.TempDir(), "resources.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, name := range []string{"older-skill", "newer-skill"} {
		if err := search.InsertResource(db, search.Resource{
			Type: "skill", Name: name, Source: "builtin",
			Description: name,
		}); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/resources?type=skill", nil)
	rec := httptest.NewRecorder()
	NewRouter(db, t.TempDir(), nil, nil, "").ServeHTTP(rec, req)

	var body struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Items) < 2 || body.Items[0].Name != "newer-skill" || body.Items[1].Name != "older-skill" {
		t.Fatalf("items = %+v, want newer-skill then older-skill", body.Items)
	}
}

func TestListResourcesFiltersVulnsByNormalizedProductAndSeverity(t *testing.T) {
	db, err := storage.OpenDB(filepath.Join(t.TempDir(), "filters.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	for _, resource := range []search.Resource{
		{
			Type: "vuln", Name: "CVE-2021-44228", Source: "builtin", Category: "middleware",
			Description: "weblogic remote code execution",
			Metadata:    `{"severity":"CRITICAL","product":"weblogic"}`,
		},
		{
			Type: "vuln", Name: "CVE-2023-0002", Source: "nuclei", Category: "nuclei-cve",
			Description: "weblogic server information disclosure",
			Metadata:    `{"severity":"HIGH","product":"weblogic_server"}`,
		},
		{
			Type: "vuln", Name: "CVE-2023-0003", Source: "builtin", Category: "web",
			Description: "openssl memory corruption",
			Metadata:    `{"severity":"LOW","product":"OpenSSL"}`,
		},
	} {
		if err := search.InsertResource(db, resource); err != nil {
			t.Fatal(err)
		}
	}
	router := NewRouter(db, t.TempDir(), nil, nil, "")

	// The listing branch used to ignore severity/product entirely.
	req := httptest.NewRequest(http.MethodGet, "/api/resources?type=vuln&product=WebLogic", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var listed struct {
		Total int `json:"total"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if listed.Total != 2 {
		t.Errorf("product=WebLogic: total = %d, want 2", listed.Total)
	}

	// The query branch used to drop product and rely on its own ToUpper.
	req = httptest.NewRequest(http.MethodGet, "/api/resources?type=vuln&q=weblogic&severity=critical&product=WebLogic", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var searched struct {
		Total int `json:"total"`
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&searched); err != nil {
		t.Fatal(err)
	}
	if searched.Total != 1 || len(searched.Items) != 1 || searched.Items[0].Name != "CVE-2021-44228" {
		t.Errorf("query+filters = %+v, want only CVE-2021-44228", searched)
	}
}
