package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

// NewRouter creates the HTTP mux with REST endpoints.
// mcpHandler is optional -- if non-nil, it's mounted at /mcp/.
func NewRouter(db *sql.DB, dataDir, apiKey string, mcpHandler http.Handler) http.Handler {
	mux := http.NewServeMux()

	// MCP endpoint — strip /mcp prefix so go-sdk sees /sse and /message
	if mcpHandler != nil {
		mux.Handle("/mcp/", http.StripPrefix("/mcp", mcpHandler))
	}

	// REST API endpoints
	mux.HandleFunc("GET /api/health", handleHealth(db))
	mux.HandleFunc("GET /api/stats", handleStats(db))

	// Apply auth middleware
	return AuthMiddleware(apiKey)(mux)
}

func handleHealth(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var count int
		err := db.QueryRow("SELECT count(*) FROM resources").Scan(&count)
		status := "ok"
		if err != nil {
			status = "error"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":          status,
			"total_resources": count,
		})
	}
}

func handleStats(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query("SELECT type, source, count(*) FROM resources GROUP BY type, source")
		if err != nil {
			http.Error(w, err.Error(), 500)
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
			rows.Scan(&s.Type, &s.Source, &s.Count)
			stats = append(stats, s)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"stats": stats})
	}
}
