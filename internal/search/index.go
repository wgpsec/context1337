package search

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/wgpsec/context1337/internal/fts"
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
	Description string
	Body        string
	Metadata    string
	Enabled     bool
}

// ResourceVisibility controls whether a query can see disabled resources.
// The zero value intentionally preserves the MCP-safe enabled-only behavior.
type ResourceVisibility uint8

const (
	VisibilityEnabledOnly ResourceVisibility = iota
	VisibilityAll
	VisibilityDisabledOnly
)

// SearchQuery defines search parameters.
type SearchQuery struct {
	Query      string
	Type       string
	Category   string
	Source     string
	Severity   string // vuln metadata filter: CRITICAL|HIGH|MEDIUM|LOW
	Product    string // vuln metadata filter: product name
	Visibility ResourceVisibility
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
	Type     string
	Category string
	Severity string // vuln metadata filter: CRITICAL|HIGH|MEDIUM|LOW
	Product  string // vuln metadata filter: product name
	Offset   int
	Limit    int
}

// ListResult wraps a page of resources with total count.
type ListResult struct {
	Total int
	Items []Resource
}

// ReindexFTS rebuilds the full-text index from the raw resources table using
// the same tokenizer used to plan queries.
func ReindexFTS(db *sql.DB) error {
	return fts.Reindex(db)
}

// InsertResource inserts a resource into the resources table (raw text) and
// populates the self-contained FTS index with tokenized text.
func InsertResource(db *sql.DB, r Resource) error {
	res, err := db.Exec(`
		INSERT OR REPLACE INTO resources
			(type, name, source, file_path, category, tags, description, body, metadata, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		r.Type, r.Name, r.Source, r.FilePath, r.Category,
		r.Tags, r.Description, r.Body, r.Metadata,
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	return IndexFTS(db, id, r.Name, r.Description, r.Tags, r.Category, r.Body)
}

// IndexFTS (re)populates the FTS row for a resource id. Every searchable field
// uses the shared tokenizer so indexing and query planning follow one contract.
func IndexFTS(db *sql.DB, id int64, name, description, tags, category, body string) error {
	return fts.Replace(db, id, fts.Fields{
		Name: name, Description: description, Tags: tags, Category: category, Body: body,
	})
}

// DeleteResource removes a resource by type, name, and source.
func DeleteResource(db *sql.DB, typ, name, source string) error {
	var id int64
	err := db.QueryRow("SELECT id FROM resources WHERE type=? AND name=? AND source=?", typ, name, source).Scan(&id)
	if err == nil {
		db.Exec("DELETE FROM resources_fts WHERE rowid = ?", id)
	}
	_, err = db.Exec("DELETE FROM resources WHERE type=? AND name=? AND source=?", typ, name, source)
	return err
}

// Search performs a full-text search against the FTS5 index.
// Returns matching results, total count (before LIMIT/OFFSET), and error.
func Search(db *sql.DB, q SearchQuery) ([]SearchResult, int, error) {
	if q.Limit <= 0 {
		q.Limit = 10
	}

	plan, err := PlanQuery(q.Query)
	if err != nil {
		return nil, 0, err
	}
	if len(plan.Groups) == 0 {
		return nil, 0, nil
	}
	ftsQuery := plan.FTSExpression
	if q.Type == "vuln" {
		ftsQuery = plan.ExactFTSExpression
	}

	var conditions []string
	var args []interface{}

	conditions = append(conditions, "resources_fts MATCH ?")
	args = append(args, ftsQuery)
	switch q.Visibility {
	case VisibilityAll:
	case VisibilityDisabledOnly:
		conditions = append(conditions, "r.enabled = 0")
	default:
		conditions = append(conditions, "r.enabled = 1")
	}

	if q.Type != "" {
		conditions = append(conditions, "r.type = ?")
		args = append(args, q.Type)
	}
	if q.Category != "" {
		conditions = append(conditions, "LOWER(r.category) = LOWER(?)")
		args = append(args, q.Category)
	}
	if q.Source != "" {
		conditions = append(conditions, "r.source = ?")
		args = append(args, q.Source)
	}
	// Exclude vuln from default search (no type specified)
	if q.Type == "" {
		conditions = append(conditions, "r.type != 'vuln'")
	}
	// Metadata filters (vuln-specific)
	if q.Severity != "" {
		conditions = append(conditions, "json_extract(r.metadata, '$.severity') = ?")
		args = append(args, q.Severity)
	}
	if q.Product != "" {
		conditions = append(conditions, "json_extract(r.metadata, '$.product') = ?")
		args = append(args, q.Product)
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
		       COALESCE(r.category,''), COALESCE(r.tags,''),
		       COALESCE(r.description,''), '', COALESCE(r.metadata,''), r.enabled,
		       bm25(resources_fts, 10.0, 5.0, 5.0, 2.0, 1.0) AS score
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
			&sr.Category, &sr.Tags,
			&sr.Description, &sr.Body, &sr.Metadata, &sr.Enabled,
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
	if q.Type != "vuln" {
		rankCandidates(plan, results)
	}
	return results, total, nil
}

// FallbackSearch reports whether SearchWithFallback attempted or used pinyin.
type FallbackSearch struct {
	Attempted        bool
	Used             bool
	Query            string
	Transliterations []QueryTransliteration
}

// SearchWithFallback runs the exact query first. If that returns zero rows at
// offset 0, it retries once with deterministic Han-to-pinyin context rewrite.
func SearchWithFallback(db *sql.DB, q SearchQuery) ([]SearchResult, int, FallbackSearch, error) {
	results, total, err := Search(db, q)
	if err != nil || total > 0 || q.Offset != 0 {
		return results, total, FallbackSearch{}, err
	}
	plan, planErr := PlanQuery(q.Query)
	if planErr != nil {
		return results, total, FallbackSearch{}, nil
	}
	fallback, ok := BuildPinyinFallback(plan)
	if !ok {
		return results, total, FallbackSearch{}, nil
	}
	info := FallbackSearch{
		Attempted:        true,
		Query:            fallback.Query,
		Transliterations: fallback.Transliterations,
	}
	fallbackQuery := q
	fallbackQuery.Query = fallback.Query
	fallbackResults, fallbackTotal, fallbackErr := Search(db, fallbackQuery)
	if fallbackErr != nil || fallbackTotal == 0 {
		return results, total, info, nil
	}
	info.Used = true
	return fallbackResults, fallbackTotal, info, nil
}

// ListByType returns resources of a given type with pagination and total count.
func ListByType(db *sql.DB, q ListQuery) (ListResult, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}

	var conditions []string
	var args []interface{}

	conditions = append(conditions, "enabled = 1")

	if q.Type != "" {
		conditions = append(conditions, "type = ?")
		args = append(args, q.Type)
	}

	if q.Category != "" {
		conditions = append(conditions, "LOWER(category) = LOWER(?)")
		args = append(args, q.Category)
	}
	// Exclude vuln from default list (no type specified)
	if q.Type == "" {
		conditions = append(conditions, "type != 'vuln'")
	}
	// Metadata filters (vuln-specific)
	if q.Severity != "" {
		conditions = append(conditions, "json_extract(metadata, '$.severity') = ?")
		args = append(args, q.Severity)
	}
	if q.Product != "" {
		conditions = append(conditions, "json_extract(metadata, '$.product') = ?")
		args = append(args, q.Product)
	}

	where := "1=1"
	if len(conditions) > 0 {
		where = strings.Join(conditions, " AND ")
	}

	// Count total matching rows.
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM resources WHERE %s", where)
	var total int
	if err := db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return ListResult{}, fmt.Errorf("count: %w", err)
	}

	// Fetch the page.
	pageArgs := append(args, q.Limit, q.Offset)
	query := fmt.Sprintf("SELECT id, type, COALESCE(name,''), COALESCE(source,''), COALESCE(file_path,''), COALESCE(category,''), COALESCE(tags,''), COALESCE(description,''), COALESCE(metadata,'') FROM resources WHERE %s ORDER BY name LIMIT ? OFFSET ?", where)

	rows, err := db.Query(query, pageArgs...)
	if err != nil {
		return ListResult{}, err
	}
	defer rows.Close()

	var res []Resource
	for rows.Next() {
		var r Resource
		err := rows.Scan(&r.ID, &r.Type, &r.Name, &r.Source, &r.FilePath,
			&r.Category, &r.Tags, &r.Description, &r.Metadata)
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
		       COALESCE(category,''), COALESCE(tags,''),
		       COALESCE(description,''), COALESCE(body,''), COALESCE(metadata,'')
		FROM resources WHERE type=? AND name=? AND enabled = 1 LIMIT 1`, typ, name).Scan(
		&r.ID, &r.Type, &r.Name, &r.Source, &r.FilePath,
		&r.Category, &r.Tags,
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
