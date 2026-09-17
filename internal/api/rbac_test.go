package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/wgpsec/context1337/internal/auth"
	"github.com/wgpsec/context1337/internal/search"
	"github.com/wgpsec/context1337/internal/storage"
	"github.com/wgpsec/context1337/internal/usage"
)

type rbacFixture struct {
	router    http.Handler
	builtinID int64
	teamID    int64
	customID  int64
}

func setupRBAC(t *testing.T) rbacFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.OpenDB(filepath.Join(dir, "rbac.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	insert := func(r search.Resource) int64 {
		t.Helper()
		if err := search.InsertResource(db, r); err != nil {
			t.Fatal(err)
		}
		var id int64
		if err := db.QueryRow("SELECT id FROM resources WHERE type=? AND name=? AND source=?", r.Type, r.Name, r.Source).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	builtinID := insert(search.Resource{
		Type: "skill", Name: "public-skill", Source: "builtin",
		Description: "public seeyon marker", Body: "public seeyon marker",
	})
	teamID := insert(search.Resource{
		Type: "skill", Name: "private-skill", Source: "team",
		Description: "private seeyon marker", Body: "private seeyon marker",
	})
	customID := insert(search.Resource{
		Type: "skill", Name: "custom-skill", Source: "custom",
		Description: "custom seeyon marker", Body: "custom seeyon marker",
	})
	insert(search.Resource{
		Type: "vuln", Name: "NUCLEI-1", Source: "nuclei",
		Description: "nuclei seeyon marker", Body: "nuclei seeyon marker",
	})

	keysPath := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(keysPath, []byte(`[
		{"id":"public-mcp","key":"pub","sources":["builtin"],"access":"read"},
		{"id":"pojun-agent","key":"agent","sources":["builtin","team"],"access":"read"},
		{"id":"ops","key":"ops","sources":["builtin","team","custom"],"access":"write"},
		{"id":"toggle-only","key":"toggle","sources":["builtin","team"],"access":"write"}
	]`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := auth.Load("admin", keysPath)
	if err != nil {
		t.Fatal(err)
	}
	collector := usage.NewCollector()
	return rbacFixture{
		router:    NewRouter(db, dir, store, nil, "", UsageEndpoint{Collector: collector}),
		builtinID: builtinID,
		teamID:    teamID,
		customID:  customID,
	}
}

func rbacDo(t *testing.T, router http.Handler, method, path, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestRBACBuiltinReadHidesTeam(t *testing.T) {
	fx := setupRBAC(t)

	rec := rbacDo(t, fx.router, http.MethodGet, "/api/resources?q=seeyon", "pub", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var list struct {
		Items []struct {
			Name   string `json:"name"`
			Source string `json:"source"`
		} `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) == 0 {
		t.Fatal("expected builtin/nuclei hits")
	}
	for _, item := range list.Items {
		if item.Source == "team" || item.Source == "custom" {
			t.Fatalf("unscoped search leaked %s: %+v", item.Source, item)
		}
	}

	rec = rbacDo(t, fx.router, http.MethodGet, "/api/resources?source=team", "pub", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("source=team status = %d, want 403", rec.Code)
	}

	rec = rbacDo(t, fx.router, http.MethodGet, "/api/resources?source=nuclei", "pub", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("source=nuclei status = %d, want 200", rec.Code)
	}

	rec = rbacDo(t, fx.router, http.MethodGet, "/api/stats", "pub", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("stats status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `"team"`) {
		t.Fatalf("stats leaked team: %s", rec.Body.String())
	}

	for _, path := range []string{
		"/api/usage",
	} {
		rec = rbacDo(t, fx.router, http.MethodGet, path, "pub", "")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s status = %d, want 403", path, rec.Code)
		}
	}
	rec = rbacDo(t, fx.router, http.MethodPost, "/api/resources", "pub", `{"type":"skill","name":"x"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST status = %d, want 403", rec.Code)
	}
	rec = rbacDo(t, fx.router, http.MethodPut, "/api/resources/"+itoa(fx.builtinID)+"/toggle", "pub", `{"enabled":false}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("toggle status = %d, want 403", rec.Code)
	}
}

func TestRBACWriteCustomAndToggleScope(t *testing.T) {
	fx := setupRBAC(t)

	rec := rbacDo(t, fx.router, http.MethodPost, "/api/resources", "ops", `{"type":"skill","name":"ops-custom","description":"n"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ops POST status = %d body=%s", rec.Code, rec.Body.String())
	}
	rec = rbacDo(t, fx.router, http.MethodPut, "/api/resources/"+itoa(fx.builtinID), "ops", `{"description":"nope"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ops PUT builtin status = %d, want 403", rec.Code)
	}
	rec = rbacDo(t, fx.router, http.MethodGet, "/api/usage", "ops", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("ops usage status = %d", rec.Code)
	}

	rec = rbacDo(t, fx.router, http.MethodPost, "/api/resources", "toggle", `{"type":"skill","name":"toggle-custom"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("toggle-only POST status = %d, want 403", rec.Code)
	}
	rec = rbacDo(t, fx.router, http.MethodPut, "/api/resources/"+itoa(fx.teamID)+"/toggle", "toggle", `{"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle team status = %d body=%s", rec.Code, rec.Body.String())
	}
	rec = rbacDo(t, fx.router, http.MethodPut, "/api/resources/"+itoa(fx.customID)+"/toggle", "toggle", `{"enabled":false}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("toggle ungranted custom status = %d, want 404", rec.Code)
	}
	rec = rbacDo(t, fx.router, http.MethodPut, "/api/resources/batch-toggle", "toggle", `{"enabled":false,"filter":{"source":"custom"}}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("batch-toggle custom status = %d, want 403", rec.Code)
	}
}

func TestRBACAgentCanSeeTeam(t *testing.T) {
	fx := setupRBAC(t)
	rec := rbacDo(t, fx.router, http.MethodGet, "/api/resources?source=team", "agent", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "private-skill") {
		t.Fatalf("agent missed team resource: %s", rec.Body.String())
	}
	rec = rbacDo(t, fx.router, http.MethodPost, "/api/resources", "agent", `{"type":"skill","name":"x"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("agent POST status = %d, want 403", rec.Code)
	}
}

func itoa(id int64) string {
	return strconv.FormatInt(id, 10)
}
