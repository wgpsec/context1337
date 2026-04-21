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
	Offset     int
	Limit      int
}

// SearchResult is a Resource with a relevance score.
type SearchResult struct {
	Resource
	Score float64
}

// ListQuery defines list/filter parameters with pagination.
type ListQuery struct {
	Type       string
	Category   string
	Difficulty string
	Offset     int
	Limit      int
}

// ListResult wraps a page of resources with total count.
type ListResult struct {
	Total int
	Items []Resource
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
// Returns matching results, total count (before LIMIT/OFFSET), and error.
func Search(db *sql.DB, q SearchQuery) ([]SearchResult, int, error) {
	if q.Limit <= 0 {
		q.Limit = 10
	}

	tokens := Tokenize(q.Query)
	if len(tokens) == 0 {
		return nil, 0, nil
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
		conditions = append(conditions, "LOWER(r.category) = LOWER(?)")
		args = append(args, q.Category)
	}
	if q.Difficulty != "" {
		conditions = append(conditions, "LOWER(r.difficulty) = LOWER(?)")
		args = append(args, q.Difficulty)
	}

	where := strings.Join(conditions, " AND ")

	// Count total matching rows.
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM resources_fts JOIN resources r ON r.id = resources_fts.rowid WHERE %s`, where)
	var total int
	if err := db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count: %w", err)
	}

	// Fetch the page.
	pageArgs := append(args, q.Limit, q.Offset)

	query := fmt.Sprintf(`
		SELECT r.id, r.type, COALESCE(r.name,''), COALESCE(r.source,''), COALESCE(r.file_path,''),
		       COALESCE(r.category,''), COALESCE(r.tags,''), COALESCE(r.mitre,''), COALESCE(r.difficulty,''),
		       COALESCE(r.description,''), COALESCE(r.body,''), COALESCE(r.metadata,''),
		       bm25(resources_fts) AS score
		FROM resources_fts
		JOIN resources r ON r.id = resources_fts.rowid
		WHERE %s
		ORDER BY score
		LIMIT ? OFFSET ?`, where)

	rows, err := db.Query(query, pageArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("search: %w", err)
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
			return nil, 0, fmt.Errorf("scan: %w", err)
		}
		results = append(results, sr)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return results, total, nil
}

// ListByType returns resources of a given type with pagination and total count.
func ListByType(db *sql.DB, q ListQuery) (ListResult, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}

	var conditions []string
	var args []interface{}

	conditions = append(conditions, "type = ?")
	args = append(args, q.Type)

	if q.Category != "" {
		conditions = append(conditions, "LOWER(category) = LOWER(?)")
		args = append(args, q.Category)
	}
	if q.Difficulty != "" {
		conditions = append(conditions, "LOWER(difficulty) = LOWER(?)")
		args = append(args, q.Difficulty)
	}

	where := strings.Join(conditions, " AND ")

	// Count total matching rows.
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM resources WHERE %s", where)
	var total int
	if err := db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return ListResult{}, fmt.Errorf("count: %w", err)
	}

	// Fetch the page.
	pageArgs := append(args, q.Limit, q.Offset)
	query := fmt.Sprintf("SELECT id, type, COALESCE(name,''), COALESCE(source,''), COALESCE(file_path,''), COALESCE(category,''), COALESCE(tags,''), COALESCE(mitre,''), COALESCE(difficulty,''), COALESCE(description,''), COALESCE(metadata,'') FROM resources WHERE %s ORDER BY name LIMIT ? OFFSET ?", where)

	rows, err := db.Query(query, pageArgs...)
	if err != nil {
		return ListResult{}, err
	}
	defer rows.Close()

	var res []Resource
	for rows.Next() {
		var r Resource
		err := rows.Scan(&r.ID, &r.Type, &r.Name, &r.Source, &r.FilePath,
			&r.Category, &r.Tags, &r.Mitre, &r.Difficulty, &r.Description, &r.Metadata)
		if err != nil {
			return ListResult{}, err
		}
		res = append(res, r)
	}
	if err := rows.Err(); err != nil {
		return ListResult{}, err
	}
	return ListResult{Total: total, Items: res}, nil
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
