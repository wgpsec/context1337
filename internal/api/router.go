package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/wgpsec/context1337/internal/auth"
	"github.com/wgpsec/context1337/internal/usage"
)

type UsageEndpoint struct {
	Collector *usage.Collector
}

// recoverMiddleware turns a handler panic into an explicit 500.
//
// net/http already survives a handler panic, and the deferred bookkeeping in
// usage.Collector still runs while the stack unwinds, so nothing leaks. What it
// does not do is set a status code: the response was never written, so the usage
// collector records the request as a 200 and /admin/usage reports a crash as a
// success. It also closes the connection silently, and the stack trace it logs
// can contain request body content, which for this service is custom resource
// text. Handlers stay free to panic on programming errors; this is the one place
// that decides what the client and the logs see.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			recovered := recover()
			if recovered == nil {
				return
			}
			// http.ErrAbortHandler is the documented way for a handler to abort
			// a response deliberately; it is not a fault and must stay silent.
			// recover() yields any value, so the panic payload may not be an
			// error at all — hence the type assertion rather than errors.Is.
			if err, ok := recovered.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(recovered)
			}
			log.Printf("panic serving %s %s: %v", r.Method, r.URL.Path, recovered)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		}()
		next.ServeHTTP(w, r)
	})
}

// NewRouter creates the HTTP mux with REST endpoints.
// mcpHandler is optional -- if non-nil, it's mounted at /mcp/.
func NewRouter(db *sql.DB, dataDir string, store *auth.Store, mcpHandler http.Handler, adminKey string, usageEndpoints ...UsageEndpoint) http.Handler {
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

	// Usage analytics reuse write keys. With authentication disabled, the
	// endpoint stays disabled rather than exposing platform telemetry publicly.
	var collector *usage.Collector
	if len(usageEndpoints) > 0 {
		collector = usageEndpoints[0].Collector
	}
	if collector != nil {
		mux.Handle("GET /api/usage", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !store.Enabled() {
				http.NotFound(w, r)
				return
			}
			handleUsage(usageEndpoints[0]).ServeHTTP(w, r)
		}))
	} else {
		mux.HandleFunc("GET /api/usage", http.NotFound)
	}
	if strings.TrimSpace(adminKey) != "" {
		admin := newAdminServer(db, store, adminKey, collector)
		mux.Handle("/admin", admin)
		mux.Handle("/admin/", admin)
	}
	// Recovery sits inside auth so an unauthenticated request cannot reach a
	// handler; auth itself only compares keys and does not deserve a recover.
	return AuthMiddleware(store)(recoverMiddleware(mux))
}

func handleUsage(endpoint UsageEndpoint) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireWrite(w, r) {
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(endpoint.Collector.Snapshot())
	})
}

// handleHealth reports enabled resource counts per type. It always counts
// enabled resources only: the numbers are published as availability, and a
// disabled resource is not available.
func handleHealth(db *sql.DB) http.HandlerFunc {
	// type → JSON field name
	typeKey := map[string]string{
		"skill":   "skills",
		"vuln":    "vulns",
		"dict":    "dicts",
		"payload": "payloads",
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRead(w, r) {
			return
		}
		where := []string{"enabled = 1"}
		var args []interface{}
		where, args = appendSourceAllowlist(where, args, "source", principalOf(r))
		query := "SELECT type, count(*) FROM resources WHERE " + strings.Join(where, " AND ") + " GROUP BY type"
		rows, err := db.Query(query, args...)
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

// statsEnabledClause maps the `enabled` query value onto a WHERE term using the
// same vocabulary as handleListResources. An absent value keeps the historical
// default of enabled-only counting, so existing callers see no change.
func statsEnabledClause(value string) (string, bool) {
	switch value {
	case "false":
		return "enabled = 0", true
	case "all":
		return "", false
	case "true", "":
		return "enabled = 1", true
	default:
		return "enabled = 1", true
	}
}

// handleStats reports resource counts, optionally grouped by category.
//
// Without `group` the response is the historical type x source breakdown and
// carries no `group` key; clients that do not know about grouping keep working
// byte for byte. With `group=category` the same filters are applied but the
// rows are bucketed per type and category, including the empty-category bucket,
// so a facet list always sums back to the type totals from /api/health.
func handleStats(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRead(w, r) {
			return
		}
		group := strings.TrimSpace(r.URL.Query().Get("group"))
		if group != "" && group != "category" {
			http.Error(w, `{"error":"unsupported group"}`, http.StatusBadRequest)
			return
		}

		where := []string{}
		var args []interface{}
		if clause, ok := statsEnabledClause(r.URL.Query().Get("enabled")); ok {
			where = append(where, clause)
		}
		where, args = appendSourceAllowlist(where, args, "source", principalOf(r))

		whereClause := ""
		if len(where) > 0 {
			whereClause = " WHERE " + strings.Join(where, " AND ")
		}

		if group == "category" {
			type facet struct {
				Type     string `json:"type"`
				Category string `json:"category"`
				Count    int    `json:"count"`
			}
			rows, err := db.Query(
				"SELECT type, COALESCE(category, ''), count(*) FROM resources"+whereClause+
					" GROUP BY type, COALESCE(category, '') ORDER BY type, count(*) DESC",
				args...,
			)
			if err != nil {
				http.Error(w, `{"error":"internal server error"}`, 500)
				return
			}
			defer rows.Close()

			facets := []facet{}
			for rows.Next() {
				var f facet
				if err := rows.Scan(&f.Type, &f.Category, &f.Count); err != nil {
					continue
				}
				facets = append(facets, f)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"group": group, "stats": facets})
			return
		}

		query := "SELECT type, source, count(*) FROM resources" + whereClause + " GROUP BY type, source"
		rows, err := db.Query(query, args...)
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
