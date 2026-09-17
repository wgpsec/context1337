package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wgpsec/context1337/internal/auth"
	"github.com/wgpsec/context1337/internal/search"
	"github.com/wgpsec/context1337/internal/storage"
	"github.com/wgpsec/context1337/internal/usage"
)

func setupAdminRouter(t *testing.T, mcpKey, adminKey string) (http.Handler, *sql.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.OpenDB(filepath.Join(dir, "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := search.InsertResource(db, search.Resource{
		Type: "skill", Name: "admin-skill", Source: "builtin",
		Description: "admin console skill", Body: "admin console skill",
	}); err != nil {
		t.Fatal(err)
	}
	store, err := auth.Open(mcpKey, filepath.Join(dir, "runtime", "api-keys.json"), true)
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter(db, dir, store, nil, adminKey, UsageEndpoint{Collector: usage.NewCollector()})
	return router, db
}

func TestAdminConsoleDisabled(t *testing.T) {
	router, _ := setupAdminRouter(t, "mcp-key", "")
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestAdminConsoleLoginAndManage(t *testing.T) {
	router, db := setupAdminRouter(t, "mcp-key", "console-key")

	page := httptest.NewRecorder()
	router.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "context1337") {
		t.Fatalf("admin page status=%d body=%s", page.Code, page.Body.String())
	}

	denied := httptest.NewRecorder()
	router.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "/admin/api/stats", nil))
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated stats = %d", denied.Code)
	}

	wrong := postJSON(router, "/admin/api/login", `{"key":"mcp-key"}`)
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("mcp key login status = %d", wrong.Code)
	}

	rest := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	req.Header.Set("Authorization", "Bearer console-key")
	router.ServeHTTP(rest, req)
	if rest.Code != http.StatusUnauthorized {
		t.Fatalf("admin key accepted as REST key: %d", rest.Code)
	}

	login := postJSON(router, "/admin/api/login", `{"key":"console-key"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%s", login.Code, login.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == adminCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("session cookie missing")
	}

	stats := httptest.NewRecorder()
	statsReq := httptest.NewRequest(http.MethodGet, "/admin/api/stats", nil)
	statsReq.AddCookie(cookie)
	router.ServeHTTP(stats, statsReq)
	if stats.Code != http.StatusOK {
		t.Fatalf("stats status = %d body=%s", stats.Code, stats.Body.String())
	}

	var builtinID int64
	if err := db.QueryRow("SELECT id FROM resources WHERE name = ?", "admin-skill").Scan(&builtinID); err != nil {
		t.Fatal(err)
	}
	toggle := httptest.NewRecorder()
	toggleReq := httptest.NewRequest(http.MethodPut, "/admin/api/resources/"+itoa(builtinID)+"/toggle", strings.NewReader(`{"enabled":false}`))
	toggleReq.Header.Set("Content-Type", "application/json")
	toggleReq.AddCookie(cookie)
	router.ServeHTTP(toggle, toggleReq)
	if toggle.Code != http.StatusOK {
		t.Fatalf("toggle status = %d body=%s", toggle.Code, toggle.Body.String())
	}

	create := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodPost, "/admin/api/resources", strings.NewReader(`{"type":"skill","name":"from-console","description":"x","body":"custom body"}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.AddCookie(cookie)
	router.ServeHTTP(create, createReq)
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", create.Code, create.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	detail := httptest.NewRecorder()
	detailReq := httptest.NewRequest(http.MethodGet, "/admin/api/resources/"+itoa(created.ID), nil)
	detailReq.AddCookie(cookie)
	router.ServeHTTP(detail, detailReq)
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), "custom body") {
		t.Fatalf("detail status=%d body=%s", detail.Code, detail.Body.String())
	}

	keys := httptest.NewRecorder()
	keysReq := httptest.NewRequest(http.MethodGet, "/admin/api/keys", nil)
	keysReq.AddCookie(cookie)
	router.ServeHTTP(keys, keysReq)
	var payload struct {
		Keys []struct {
			ID     string `json:"id"`
			Origin string `json:"origin"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(keys.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Keys) != 1 || payload.Keys[0].ID != "bootstrap" || payload.Keys[0].Origin != "env" {
		t.Fatalf("keys = %+v", payload.Keys)
	}
	if strings.Contains(keys.Body.String(), "mcp-key") || strings.Contains(keys.Body.String(), "console-key") {
		t.Fatalf("key material leaked: %s", keys.Body.String())
	}
}

func postJSON(handler http.Handler, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestAdminManagesAPIKeys(t *testing.T) {
	router, _ := setupAdminRouter(t, "mcp-key", "console-key")
	login := postJSON(router, "/admin/api/login", `{"key":"console-key"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d", login.Code)
	}
	var cookie *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == adminCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("session cookie missing")
	}

	create := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodPost, "/admin/api/keys", strings.NewReader(`{"id":"public-mcp","access":["read"],"sources":["builtin"]}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.AddCookie(cookie)
	router.ServeHTTP(create, createReq)
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", create.Code, create.Body.String())
	}
	var created struct {
		ID     string   `json:"id"`
		Key    string   `json:"key"`
		Origin string   `json:"origin"`
		Access []string `json:"access"`
	}
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.ID != "public-mcp" || created.Key == "" || created.Origin != "file" {
		t.Fatalf("created = %+v", created)
	}

	stats := httptest.NewRecorder()
	statsReq := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	statsReq.Header.Set("Authorization", "Bearer "+created.Key)
	router.ServeHTTP(stats, statsReq)
	if stats.Code != http.StatusOK {
		t.Fatalf("new key stats = %d body=%s", stats.Code, stats.Body.String())
	}

	forbidden := httptest.NewRecorder()
	toggleReq := httptest.NewRequest(http.MethodPut, "/api/resources/1/toggle", strings.NewReader(`{"enabled":false}`))
	toggleReq.Header.Set("Content-Type", "application/json")
	toggleReq.Header.Set("Authorization", "Bearer "+created.Key)
	router.ServeHTTP(forbidden, toggleReq)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("read key toggle = %d", forbidden.Code)
	}

	update := httptest.NewRecorder()
	updateReq := httptest.NewRequest(http.MethodPut, "/admin/api/keys/public-mcp", strings.NewReader(`{"access":["read","write"],"sources":["builtin","team","custom"]}`))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.AddCookie(cookie)
	router.ServeHTTP(update, updateReq)
	if update.Code != http.StatusOK {
		t.Fatalf("update status = %d body=%s", update.Code, update.Body.String())
	}

	rotate := httptest.NewRecorder()
	rotateReq := httptest.NewRequest(http.MethodPost, "/admin/api/keys/public-mcp/rotate", nil)
	rotateReq.AddCookie(cookie)
	router.ServeHTTP(rotate, rotateReq)
	var rotated struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(rotate.Body).Decode(&rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Key == "" || rotated.Key == created.Key {
		t.Fatalf("rotated = %+v", rotated)
	}
	old := httptest.NewRecorder()
	oldReq := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	oldReq.Header.Set("Authorization", "Bearer "+created.Key)
	router.ServeHTTP(old, oldReq)
	if old.Code != http.StatusUnauthorized {
		t.Fatalf("old key still works: %d", old.Code)
	}

	envDenied := httptest.NewRecorder()
	envReq := httptest.NewRequest(http.MethodDelete, "/admin/api/keys/bootstrap", nil)
	envReq.AddCookie(cookie)
	router.ServeHTTP(envDenied, envReq)
	if envDenied.Code != http.StatusForbidden {
		t.Fatalf("delete bootstrap = %d", envDenied.Code)
	}

	del := httptest.NewRecorder()
	delReq := httptest.NewRequest(http.MethodDelete, "/admin/api/keys/public-mcp", nil)
	delReq.AddCookie(cookie)
	router.ServeHTTP(del, delReq)
	if del.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", del.Code, del.Body.String())
	}
	gone := httptest.NewRecorder()
	goneReq := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	goneReq.Header.Set("Authorization", "Bearer "+rotated.Key)
	router.ServeHTTP(gone, goneReq)
	if gone.Code != http.StatusUnauthorized {
		t.Fatalf("deleted key still works: %d", gone.Code)
	}
}

func TestAdminWriteOnlyKeyCannotRead(t *testing.T) {
	router, db := setupAdminRouter(t, "mcp-key", "console-key")
	login := postJSON(router, "/admin/api/login", `{"key":"console-key"}`)
	var cookie *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == adminCookieName {
			cookie = c
		}
	}
	create := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodPost, "/admin/api/keys", strings.NewReader(`{"id":"writer","access":["write"],"sources":["builtin"]}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.AddCookie(cookie)
	router.ServeHTTP(create, createReq)
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", create.Code, create.Body.String())
	}
	var created struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	stats := httptest.NewRecorder()
	statsReq := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	statsReq.Header.Set("Authorization", "Bearer "+created.Key)
	router.ServeHTTP(stats, statsReq)
	if stats.Code != http.StatusForbidden {
		t.Fatalf("write-only stats = %d", stats.Code)
	}

	var builtinID int64
	if err := db.QueryRow("SELECT id FROM resources WHERE name = ?", "admin-skill").Scan(&builtinID); err != nil {
		t.Fatal(err)
	}
	toggle := httptest.NewRecorder()
	toggleReq := httptest.NewRequest(http.MethodPut, "/admin/api/resources/"+itoa(builtinID)+"/toggle", strings.NewReader(`{"enabled":false}`))
	toggleReq.Header.Set("Content-Type", "application/json")
	toggleReq.Header.Set("Authorization", "Bearer "+created.Key)
	router.ServeHTTP(toggle, toggleReq)
	if toggle.Code != http.StatusUnauthorized {
		t.Fatalf("mcp key must not use admin routes: %d", toggle.Code)
	}

	toggleREST := httptest.NewRecorder()
	toggleRESTReq := httptest.NewRequest(http.MethodPut, "/api/resources/"+itoa(builtinID)+"/toggle", strings.NewReader(`{"enabled":false}`))
	toggleRESTReq.Header.Set("Content-Type", "application/json")
	toggleRESTReq.Header.Set("Authorization", "Bearer "+created.Key)
	router.ServeHTTP(toggleREST, toggleRESTReq)
	if toggleREST.Code != http.StatusOK {
		t.Fatalf("write-only toggle = %d body=%s", toggleREST.Code, toggleREST.Body.String())
	}
}
