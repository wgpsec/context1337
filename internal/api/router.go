package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/wgpsec/context1337/internal/usage"
)

type UsageEndpoint struct {
	Collector *usage.Collector
}

// NewRouter creates the HTTP mux with REST endpoints.
// mcpHandler is optional -- if non-nil, it's mounted at /mcp/.
func NewRouter(db *sql.DB, dataDir, apiKey string, mcpHandler http.Handler, usageEndpoints ...UsageEndpoint) http.Handler {
	mux := http.NewServeMux()

	// MCP endpoint — Streamable HTTP handler mounted at /mcp
	if mcpHandler != nil {
		mux.Handle("/mcp", mcpHandler)
	}

	// Liveness probe — no auth required (exempted in AuthMiddleware)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "OK")
	})

	// REST API endpoints
	mux.HandleFunc("GET /api/health", handleHealth(db))
	mux.HandleFunc("GET /api/stats", handleStats(db))
	mux.HandleFunc("GET /api/resources", handleListResources(db))
	mux.HandleFunc("POST /api/resources", handleCreateResource(db))
	mux.HandleFunc("PUT /api/resources/batch-toggle", handleBatchToggle(db))
	mux.HandleFunc("PUT /api/resources/{id}", handleUpdateResource(db))
	mux.HandleFunc("DELETE /api/resources/{id}", handleDeleteResource(db))
	mux.HandleFunc("PUT /api/resources/{id}/toggle", handleToggleResource(db))

	// Usage analytics reuse the MCP API key. With authentication disabled, the
	// endpoint stays disabled rather than exposing platform telemetry publicly.
	if apiKey != "" && len(usageEndpoints) > 0 && usageEndpoints[0].Collector != nil {
		mux.Handle("GET /api/usage", handleUsage(usageEndpoints[0]))
	} else {
		mux.HandleFunc("GET /api/usage", http.NotFound)
	}
	return AuthMiddleware(apiKey)(mux)
}

func handleUsage(endpoint UsageEndpoint) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(endpoint.Collector.Snapshot())
	})
}

func handleHealth(db *sql.DB) http.HandlerFunc {
	// type → JSON field name
	typeKey := map[string]string{
		"skill":   "skills",
		"vuln":    "vulns",
		"dict":    "dicts",
		"payload": "payloads",
	}

	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query("SELECT type, count(*) FROM resources WHERE enabled = 1 GROUP BY type")
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "error",
			})
			return
		}
		defer rows.Close()

		resp := map[string]interface{}{"status": "ok"}
		total := 0
		for rows.Next() {
			var typ string
			var cnt int
			if err := rows.Scan(&typ, &cnt); err != nil {
				continue
			}
			total += cnt
			if key, ok := typeKey[typ]; ok {
				resp[key] = cnt
			}
		}
		resp["total_resources"] = total
		json.NewEncoder(w).Encode(resp)
	}
}

func handleStats(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query("SELECT type, source, count(*) FROM resources WHERE enabled = 1 GROUP BY type, source")
		if err != nil {
			http.Error(w, `{"error":"internal server error"}`, 500)
			return
		}
		defer rows.Close()

		type stat struct {
			Type   string `json:"type"`
			Source string `json:"source"`
			Count  int    `json:"count"`
		}
		var stats []stat
		for rows.Next() {
			var s stat
			if err := rows.Scan(&s.Type, &s.Source, &s.Count); err != nil {
				continue
			}
			stats = append(stats, s)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"stats": stats})
	}
}
