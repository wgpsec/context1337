package search

import (
	"database/sql"
	"fmt"
	"strings"
)

// Resource represents a row in the resources table.
type Resource struct {
	ID          int64
	Type        string
	Name        string
	Source      string
	FilePath    string
	Category    string
	Tags        string
	Mitre       string
	Difficulty  string
	Description string
	Body        string
	Metadata    string
}

// SearchQuery defines search parameters.
type SearchQuery struct {
	Query      string
	Type       string
	Category   string
	Difficulty string
	Limit      int
}

// SearchResult is a Resource with a relevance score.
type SearchResult struct {
	Resource
	Score float64
}

// InsertResource inserts a resource into the resources table.
func InsertResource(db *sql.DB, r Resource) error {
	_, err := db.Exec(`
		INSERT OR REPLACE INTO resources
			(type, name, source, file_path, category, tags, mitre, difficulty, description, body, metadata, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		r.Type, r.Name, r.Source, r.FilePath, r.Category,
		r.Tags, r.Mitre, r.Difficulty, r.Description, r.Body, r.Metadata,
	)
	return err
}

// DeleteResource removes a resource by type, name, and source.
func DeleteResource(db *sql.DB, typ, name, source string) error {
	_, err := db.Exec("DELETE FROM resources WHERE type=? AND name=? AND source=?", typ, name, source)
	return err
}

// Search performs a full-text search against the FTS5 index.
func Search(db *sql.DB, q SearchQuery) ([]SearchResult, error) {
	if q.Limit <= 0 {
		q.Limit = 10
	}

	tokens := Tokenize(q.Query)
	if len(tokens) == 0 {
		return nil, nil
	}

	// Build FTS5 match expression: each token joined with OR
	// Escape double quotes in tokens
	var escaped []string
	for _, tok := range tokens {
		escaped = append(escaped, `"`+strings.ReplaceAll(tok, `"`, `""`)+`"`)
	}
	ftsQuery := strings.Join(escaped, " OR ")

	var conditions []string
	var args []interface{}

	conditions = append(conditions, "resources_fts MATCH ?")
	args = append(args, ftsQuery)

	if q.Type != "" {
		conditions = append(conditions, "r.type = ?")
		args = append(args, q.Type)
	}
	if q.Category != "" {
		conditions = append(conditions, "r.category = ?")
		args = append(args, q.Category)
	}
	if q.Difficulty != "" {
		conditions = append(conditions, "r.difficulty = ?")
		args = append(args, q.Difficulty)
	}

	where := strings.Join(conditions, " AND ")
	args = append(args, q.Limit)

	query := fmt.Sprintf(`
		SELECT r.id, r.type, COALESCE(r.name,''), COALESCE(r.source,''), COALESCE(r.file_path,''),
		       COALESCE(r.category,''), COALESCE(r.tags,''), COALESCE(r.mitre,''), COALESCE(r.difficulty,''),
		       COALESCE(r.description,''), COALESCE(r.body,''), COALESCE(r.metadata,''),
		       bm25(resources_fts) AS score
		FROM resources_fts
		JOIN resources r ON r.id = resources_fts.rowid
		WHERE %s
		ORDER BY score
		LIMIT ?`, where)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}
	defer rows.Close()

	var results []SearchResult
	for rows.Next() {
		var sr SearchResult
		err := rows.Scan(
			&sr.ID, &sr.Type, &sr.Name, &sr.Source, &sr.FilePath,
			&sr.Category, &sr.Tags, &sr.Mitre, &sr.Difficulty,
			&sr.Description, &sr.Body, &sr.Metadata,
			&sr.Score,
		)
		if err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		results = append(results, sr)
	}
	return results, rows.Err()
}

// ListByType returns all resources of a given type, optionally filtered.
func ListByType(db *sql.DB, typ, category string, limit int) ([]Resource, error) {
	if limit <= 0 {
		limit = 100
	}

	var conditions []string
	var args []interface{}

	conditions = append(conditions, "type = ?")
	args = append(args, typ)

	if category != "" {
		conditions = append(conditions, "category = ?")
		args = append(args, category)
	}

	where := strings.Join(conditions, " AND ")
	args = append(args, limit)

	query := fmt.Sprintf("SELECT id, type, COALESCE(name,''), COALESCE(source,''), COALESCE(file_path,''), COALESCE(category,''), COALESCE(tags,''), COALESCE(mitre,''), COALESCE(difficulty,''), COALESCE(description,''), COALESCE(metadata,'') FROM resources WHERE %s ORDER BY name LIMIT ?", where)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []Resource
	for rows.Next() {
		var r Resource
		err := rows.Scan(&r.ID, &r.Type, &r.Name, &r.Source, &r.FilePath,
			&r.Category, &r.Tags, &r.Mitre, &r.Difficulty, &r.Description, &r.Metadata)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, rows.Err()
}

// GetByName returns a single resource by type, name.
func GetByName(db *sql.DB, typ, name string) (*Resource, error) {
	var r Resource
	err := db.QueryRow(`
		SELECT id, type, COALESCE(name,''), COALESCE(source,''), COALESCE(file_path,''),
		       COALESCE(category,''), COALESCE(tags,''), COALESCE(mitre,''),
		       COALESCE(difficulty,''), COALESCE(description,''), COALESCE(body,''), COALESCE(metadata,'')
		FROM resources WHERE type=? AND name=? LIMIT 1`, typ, name).Scan(
		&r.ID, &r.Type, &r.Name, &r.Source, &r.FilePath,
		&r.Category, &r.Tags, &r.Mitre, &r.Difficulty,
		&r.Description, &r.Body, &r.Metadata,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}
