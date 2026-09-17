package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wgpsec/context1337/internal/auth"
	"github.com/wgpsec/context1337/internal/usage"
)

const (
	adminCookieName = "absec_admin"
	adminSessionTTL = 12 * time.Hour
)

type adminServer struct {
	db        *sql.DB
	store     *auth.Store
	key       string
	collector *usage.Collector
	mux       *http.ServeMux
}

func newAdminServer(db *sql.DB, store *auth.Store, adminKey string, collector *usage.Collector) *adminServer {
	s := &adminServer{db: db, store: store, key: strings.TrimSpace(adminKey), collector: collector, mux: http.NewServeMux()}
	wrap := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(auth.WithPrincipal(r.Context(), auth.AdminPrincipal("console")))
			h.ServeHTTP(w, r)
		})
	}
	s.mux.HandleFunc("POST /admin/api/login", s.handleLogin)
	s.mux.HandleFunc("POST /admin/api/logout", s.handleLogout)
	s.mux.HandleFunc("GET /admin/api/session", wrap(s.handleSession))
	s.mux.HandleFunc("GET /admin/api/keys", wrap(s.handleKeys))
	s.mux.HandleFunc("POST /admin/api/keys", wrap(s.handleCreateKey))
	s.mux.HandleFunc("PUT /admin/api/keys/{id}", wrap(s.handleUpdateKey))
	s.mux.HandleFunc("DELETE /admin/api/keys/{id}", wrap(s.handleDeleteKey))
	s.mux.HandleFunc("POST /admin/api/keys/{id}/rotate", wrap(s.handleRotateKey))
	s.mux.HandleFunc("GET /admin/api/health", wrap(handleHealth(db)))
	s.mux.HandleFunc("GET /admin/api/stats", wrap(handleStats(db)))
	s.mux.HandleFunc("GET /admin/api/resources", wrap(handleListResources(db)))
	s.mux.HandleFunc("GET /admin/api/resources/{id}", wrap(handleGetResource(db)))
	s.mux.HandleFunc("POST /admin/api/resources", wrap(handleCreateResource(db)))
	s.mux.HandleFunc("PUT /admin/api/resources/batch-toggle", wrap(handleBatchToggle(db)))
	s.mux.HandleFunc("PUT /admin/api/resources/{id}", wrap(handleUpdateResource(db)))
	s.mux.HandleFunc("DELETE /admin/api/resources/{id}", wrap(handleDeleteResource(db)))
	s.mux.HandleFunc("PUT /admin/api/resources/{id}/toggle", wrap(handleToggleResource(db)))
	if collector != nil {
		s.mux.Handle("GET /admin/api/usage", wrap(handleUsage(UsageEndpoint{Collector: collector}).ServeHTTP))
	} else {
		s.mux.HandleFunc("GET /admin/api/usage", wrap(http.NotFound))
	}
	return s
}

func (s *adminServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && (r.URL.Path == "/admin" || r.URL.Path == "/admin/") {
		s.handlePage(w, r)
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *adminServer) handlePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Write(adminPage)
}

func (s *adminServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(s.key), []byte(strings.TrimSpace(body.Key))) != 1 {
		http.Error(w, `{"error":"invalid admin key"}`, http.StatusUnauthorized)
		return
	}
	token, err := s.issueSession()
	if err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, s.sessionCookie(r, token, adminSessionTTL))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (s *adminServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, s.sessionCookie(r, "", -time.Hour))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (s *adminServer) handleSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": "console"})
}

func (s *adminServer) handleKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"keys": s.store.PublicPrincipals()})
}

func (s *adminServer) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	var input auth.KeyInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
		return
	}
	principal, key, err := s.store.Create(input, s.key)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"id": principal.ID, "access": principal.Access, "sources": principal.Sources,
		"origin": principal.Origin, "key": key,
	})
}

func (s *adminServer) handleUpdateKey(w http.ResponseWriter, r *http.Request) {
	var input auth.KeyInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
		return
	}
	principal, err := s.store.Update(r.PathValue("id"), input.Access, input.Sources)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(principal)
}

func (s *adminServer) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	principal, key, err := s.store.Rotate(r.PathValue("id"), s.key)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"id": principal.ID, "access": principal.Access, "sources": principal.Sources,
		"origin": principal.Origin, "key": key,
	})
}

func (s *adminServer) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Delete(r.PathValue("id")); err != nil {
		writeStoreError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func writeStoreError(w http.ResponseWriter, err error) {
	msg := err.Error()
	status := http.StatusBadRequest
	switch {
	case msg == "not found":
		status = http.StatusNotFound
	case strings.Contains(msg, "cannot be modified"):
		status = http.StatusForbidden
	case strings.Contains(msg, "duplicate"):
		status = http.StatusConflict
	case strings.Contains(msg, "not configured"), strings.Contains(msg, "write api keys"), strings.Contains(msg, "create api keys"):
		status = http.StatusInternalServerError
	}
	http.Error(w, fmt.Sprintf(`{"error":%q}`, msg), status)
}

func (s *adminServer) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(adminCookieName)
		if err != nil || !s.validSession(cookie.Value) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (s *adminServer) issueSession() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	exp := time.Now().Add(adminSessionTTL).Unix()
	nonceHex := hex.EncodeToString(nonce)
	return fmt.Sprintf("v1.%d.%s.%s", exp, nonceHex, s.sign(exp, nonceHex)), nil
}

func (s *adminServer) validSession(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	want, err := base64.RawURLEncoding.DecodeString(s.sign(exp, parts[2]))
	if err != nil {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	return hmac.Equal(want, got)
}

func (s *adminServer) sign(exp int64, nonce string) string {
	mac := hmac.New(sha256.New, s.secret())
	fmt.Fprintf(mac, "v1|%d|%s", exp, nonce)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *adminServer) secret() []byte {
	sum := sha256.Sum256([]byte("context1337-admin-session|" + s.key))
	return sum[:]
}

func (s *adminServer) sessionCookie(r *http.Request, value string, ttl time.Duration) *http.Cookie {
	maxAge := int(ttl.Seconds())
	if ttl < 0 {
		maxAge = -1
	}
	return &http.Cookie{
		Name:     adminCookieName,
		Value:    value,
		Path:     "/admin",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
	}
}
