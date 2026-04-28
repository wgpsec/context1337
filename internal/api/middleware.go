package api

import (
	"net/http"
	"strings"
)

// AuthMiddleware returns middleware that validates Bearer token.
// If apiKey is empty, auth is disabled (development mode).
// MCP endpoints (/mcp/) are exempt — MCP SSE clients may not support auth headers.
// They can pass ?api_key= as a query param instead.
func AuthMiddleware(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if apiKey == "" {
				next.ServeHTTP(w, r)
				return
			}

			// /health is exempt — used as a liveness probe with no auth required.
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			// MCP endpoints: support both Bearer header and query param
			if r.URL.Path == "/mcp" || strings.HasPrefix(r.URL.Path, "/mcp/") {
				qk := r.URL.Query().Get("api_key")
				auth := r.Header.Get("Authorization")
				token := strings.TrimPrefix(auth, "Bearer ")
				if token == apiKey || qk == apiKey {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			// REST endpoints: require Bearer header
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(auth, "Bearer ")
			if token != apiKey {
				http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
