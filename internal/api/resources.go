package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func handleListResources(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		where := []string{}
		args := []interface{}{}

		if v := q.Get("type"); v != "" {
			where = append(where, "type = ?")
			args = append(args, v)
		}
		if v := q.Get("category"); v != "" {
			where = append(where, "category = ?")
			args = append(args, v)
		}
		if v := q.Get("source"); v != "" {
			where = append(where, "source = ?")
			args = append(args, v)
		}
		switch q.Get("enabled") {
		case "true":
			where = append(where, "enabled = 1")
		case "false":
			where = append(where, "enabled = 0")
		}

		whereClause := ""
		if len(where) > 0 {
			whereClause = " WHERE " + strings.Join(where, " AND ")
		}

		var total int
		db.QueryRow("SELECT count(*) FROM resources"+whereClause, args...).Scan(&total)

		limit := 100
		if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 {
			limit = v
		}
		offset := 0
		if v, err := strconv.Atoi(q.Get("offset")); err == nil && v >= 0 {
			offset = v
		}

		rows, err := db.Query("SELECT id, type, name, category, source, description, tags, enabled FROM resources"+whereClause+" LIMIT ? OFFSET ?", append(args, limit, offset)...)
		if err != nil {
			http.Error(w, `{"error":"query failed"}`, 500)
			return
		}
		defer rows.Close()

		items := []map[string]interface{}{}
		for rows.Next() {
			var id, enabled int
			var typ, name, category, source, description, tags string
			if err := rows.Scan(&id, &typ, &name, &category, &source, &description, &tags, &enabled); err != nil {
				continue
			}
			items = append(items, map[string]interface{}{
				"id": id, "type": typ, "name": name, "category": category,
				"source": source, "description": description, "tags": tags, "enabled": enabled == 1,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"total": total, "items": items})
	}
}

func handleToggleResource(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid body"}`, 400)
			return
		}
		val := 0
		if body.Enabled {
			val = 1
		}
		res, _ := db.Exec("UPDATE resources SET enabled = ? WHERE id = ?", val, id)
		n, _ := res.RowsAffected()
		if n == 0 {
			http.Error(w, `{"error":"not found"}`, 404)
			return
		}
		var name, typ string
		db.QueryRow("SELECT name, type FROM resources WHERE id = ?", id).Scan(&name, &typ)
		w.Header().Set("Content-Type", "application/json")
		idInt, _ := strconv.Atoi(id)
		json.NewEncoder(w).Encode(map[string]interface{}{"id": idInt, "name": name, "type": typ, "enabled": body.Enabled})
	}
}

func handleBatchToggle(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enabled bool `json:"enabled"`
			Filter  struct {
				Type     string `json:"type"`
				Category string `json:"category"`
				Source   string `json:"source"`
			} `json:"filter"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid body"}`, 400)
			return
		}
		where := []string{}
		args := []interface{}{}
		val := 0
		if body.Enabled {
			val = 1
		}
		args = append(args, val)
		if body.Filter.Type != "" {
			where = append(where, "type = ?")
			args = append(args, body.Filter.Type)
		}
		if body.Filter.Category != "" {
			where = append(where, "category = ?")
			args = append(args, body.Filter.Category)
		}
		if body.Filter.Source != "" {
			where = append(where, "source = ?")
			args = append(args, body.Filter.Source)
		}
		if len(where) == 0 {
			http.Error(w, `{"error":"filter requires at least one condition"}`, 400)
			return
		}
		query := "UPDATE resources SET enabled = ? WHERE " + strings.Join(where, " AND ")
		res, _ := db.Exec(query, args...)
		n, _ := res.RowsAffected()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"affected": n})
	}
}

func handleCreateResource(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Type        string `json:"type"`
			Name        string `json:"name"`
			Category    string `json:"category"`
			Tags        string `json:"tags"`
			Difficulty  string `json:"difficulty"`
			Description string `json:"description"`
			Body        string `json:"body"`
			Metadata    string `json:"metadata"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid body"}`, 400)
			return
		}
		validTypes := map[string]bool{"skill": true, "vuln": true, "payload": true, "dict": true}
		if !validTypes[body.Type] {
			http.Error(w, `{"error":"type must be skill|vuln|payload|dict"}`, 400)
			return
		}
		if body.Name == "" {
			http.Error(w, `{"error":"name is required"}`, 400)
			return
		}
		res, err := db.Exec(
			"INSERT INTO resources (type, name, category, tags, difficulty, description, body, metadata, source, file_path) VALUES (?,?,?,?,?,?,?,?,?,?)",
			body.Type, body.Name, body.Category, body.Tags, body.Difficulty, body.Description, body.Body, body.Metadata, "custom", "",
		)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				http.Error(w, `{"error":"conflict"}`, 409)
				return
			}
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), 500)
			return
		}
		id, _ := res.LastInsertId()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]interface{}{"id": id, "name": body.Name, "type": body.Type})
	}
}

func handleUpdateResource(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var source string
		err := db.QueryRow("SELECT source FROM resources WHERE id = ?", id).Scan(&source)
		if err != nil {
			http.Error(w, `{"error":"not found"}`, 404)
			return
		}
		if source != "custom" {
			http.Error(w, `{"error":"only custom resources can be updated"}`, 403)
			return
		}
		var body struct {
			Name        *string `json:"name"`
			Category    *string `json:"category"`
			Tags        *string `json:"tags"`
			Difficulty  *string `json:"difficulty"`
			Description *string `json:"description"`
			Body        *string `json:"body"`
			Metadata    *string `json:"metadata"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid body"}`, 400)
			return
		}
		sets := []string{"updated_at = datetime('now')"}
		args := []interface{}{}
		if body.Name != nil {
			sets = append(sets, "name = ?")
			args = append(args, *body.Name)
		}
		if body.Category != nil {
			sets = append(sets, "category = ?")
			args = append(args, *body.Category)
		}
		if body.Tags != nil {
			sets = append(sets, "tags = ?")
			args = append(args, *body.Tags)
		}
		if body.Difficulty != nil {
			sets = append(sets, "difficulty = ?")
			args = append(args, *body.Difficulty)
		}
		if body.Description != nil {
			sets = append(sets, "description = ?")
			args = append(args, *body.Description)
		}
		if body.Body != nil {
			sets = append(sets, "body = ?")
			args = append(args, *body.Body)
		}
		if body.Metadata != nil {
			sets = append(sets, "metadata = ?")
			args = append(args, *body.Metadata)
		}
		args = append(args, id)
		db.Exec("UPDATE resources SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...)
		w.Header().Set("Content-Type", "application/json")
		idInt, _ := strconv.Atoi(id)
		json.NewEncoder(w).Encode(map[string]interface{}{"id": idInt, "ok": true})
	}
}

func handleDeleteResource(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var source string
		err := db.QueryRow("SELECT source FROM resources WHERE id = ?", id).Scan(&source)
		if err != nil {
			http.Error(w, `{"error":"not found"}`, 404)
			return
		}
		if source != "custom" {
			http.Error(w, `{"error":"only custom resources can be deleted"}`, 403)
			return
		}
		db.Exec("DELETE FROM resources WHERE id = ?", id)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}
}
