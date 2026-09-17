package api

import (
	"net/http"
	"strings"

	"github.com/wgpsec/context1337/internal/auth"
)

// AuthMiddleware validates Bearer tokens (and MCP query keys) against the
// principal store. An empty or disabled store is development mode: no auth,
// admin principal. /health stays unauthenticated and does not receive a
// principal, so it cannot leak source counts.
func AuthMiddleware(store *auth.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" || isAdminPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			if !store.Enabled() {
				r = r.WithContext(auth.WithPrincipal(r.Context(), auth.AdminPrincipal("anonymous")))
				next.ServeHTTP(w, r)
				return
			}

			principal, status, message := authenticateRequest(store, r)
			if message != "" {
				http.Error(w, message, status)
				return
			}
			r = r.WithContext(auth.WithPrincipal(r.Context(), principal))
			next.ServeHTTP(w, r)
		})
	}
}

func isAdminPath(path string) bool {
	return path == "/admin" || strings.HasPrefix(path, "/admin/")
}

func authenticateRequest(store *auth.Store, r *http.Request) (auth.Principal, int, string) {
	if r.URL.Path == "/mcp" || strings.HasPrefix(r.URL.Path, "/mcp/") {
		header := r.Header.Get("Authorization")
		token := strings.TrimPrefix(header, "Bearer ")
		if principal, ok := store.Lookup(token); ok {
			return principal, 0, ""
		}
		if principal, ok := store.Lookup(r.URL.Query().Get("api_key")); ok {
			return principal, 0, ""
		}
		return auth.Principal{}, http.StatusUnauthorized, `{"error":"unauthorized"}`
	}

	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return auth.Principal{}, http.StatusUnauthorized, `{"error":"missing authorization header"}`
	}
	principal, ok := store.Lookup(strings.TrimPrefix(header, "Bearer "))
	if !ok {
		return auth.Principal{}, http.StatusUnauthorized, `{"error":"invalid api key"}`
	}
	return principal, 0, ""
}
