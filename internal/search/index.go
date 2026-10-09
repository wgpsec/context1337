package search

import (
	"database/sql"
	"fmt"
	"log"
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
	Sources    []string // optional allowlist; empty means unrestricted
	Severity   string   // vuln metadata filter: CRITICAL|HIGH|MEDIUM|LOW
	Product    string   // vuln metadata filter: product name
	Visibility ResourceVisibility
	Offset     int
	Limit      int
	// SkipFallback suppresses the pinyin retry even at offset 0. Set it when
	// this query is only the fetch of a ranked candidate list on behalf of a
	// later page: such callers read from the top, so Offset can no longer say
	// whether the current request is a first page.
	SkipFallback bool
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
	Source   string
	Sources  []string // optional allowlist; empty means unrestricted
	Severity string   // vuln metadata filter: CRITICAL|HIGH|MEDIUM|LOW
	Product  string   // vuln metadata filter: product name
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
		if _, err := db.Exec("DELETE FROM resources_fts WHERE rowid = ?", id); err != nil {
			log.Printf("drop FTS row %d for %s/%s/%s: %v", id, source, typ, name, err)
		}
	}
	_, err = db.Exec("DELETE FROM resources WHERE type=? AND name=? AND source=?", typ, name, source)
	return err
}

// buildSearchFilters renders the non-FTS half of a search predicate, phrased
// over the alias `r`. It is shared with CountMatching so a row set counted by the
// retry builder is the row set a later Search returns for the same query.
func buildSearchFilters(q SearchQuery) (string, []interface{}) {
	var filters []string
	var filterArgs []interface{}

	switch q.Visibility {
	case VisibilityAll:
	case VisibilityDisabledOnly:
		filters = append(filters, "r.enabled = 0")
	default:
		filters = append(filters, "r.enabled = 1")
	}

	if q.Type != "" {
		filters = append(filters, "r.type = ?")
		filterArgs = append(filterArgs, q.Type)
	}
	if q.Category != "" {
		filters = append(filters, "LOWER(r.category) = LOWER(?)")
		filterArgs = append(filterArgs, q.Category)
	}
	filters, filterArgs = appendSourceConstraints(filters, filterArgs, "r.source", q.Source, q.Sources)
	// Exclude vuln from default search (no type specified)
	if q.Type == "" {
		filters = append(filters, "r.type != 'vuln'")
	}
	// Metadata filters (vuln-specific)
	if q.Severity != "" {
		filters = append(filters, "json_extract(r.metadata, '$.severity') = ?")
		filterArgs = append(filterArgs, q.Severity)
	}
	if q.Product != "" {
		filters = append(filters, "json_extract(r.metadata, '$.product') = ?")
		filterArgs = append(filterArgs, q.Product)
	}

	return strings.Join(filters, " AND "), filterArgs
}

// CountMatching returns how many rows a SearchQuery would match, without ranking
// or paging. It exists for the no_match retry builder, which needs to know
// whether a candidate query reaches the corpus at all before offering it: a
// suggestion that cannot return a row is worse than no suggestion.
//
// The row set is deliberately identical to Search's count, filters included, so
// "this candidate hits" means the caller's own follow-up search hits too.
func CountMatching(db *sql.DB, q SearchQuery) (int, error) {
	plan, err := PlanQuery(q.Query)
	if err != nil {
		return 0, err
	}
	if len(plan.Groups) == 0 {
		return 0, nil
	}
	ftsQuery := plan.FTSExpression
	if q.Type == "vuln" {
		ftsQuery = plan.ExactFTSExpression
	}

	filterWhere, filterArgs := buildSearchFilters(q)
	countArgs := append(append([]interface{}{}, filterArgs...), ftsQuery)

	var total int
	err = db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM resources r WHERE %s AND r.id IN
		(SELECT rowid FROM resources_fts WHERE resources_fts MATCH ?)`, filterWhere),
		countArgs...).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("count matching: %w", err)
	}
	return total, nil
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

	// Filters are split from the match expression so the count can be phrased
	// differently from the page fetch without drifting from it. Both are built
	// over the alias `r`, and MATCH is a pure filter, so the two forms below
	// describe exactly the same row set. They are built by buildSearchFilters so
	// CountMatching describes the same row set without restating the clauses.
	filterWhere, filterArgs := buildSearchFilters(q)

	// Count total matching rows.
	//
	// Phrased as "scan resources, keep the rows the FTS index matches" instead of
	// joining in match order. Both describe the same row set, but the join form
	// plans as a scan of resources through idx_resources_enabled with a
	// correlated FTS lookup per row, which cost 36ms to count two matches out of
	// a 260:1 selectivity advantage. Here the FTS index drives and the count
	// short-circuits in ~0.1ms.
	//
	// This does not reuse the page query's CTE because counting has no use for
	// bm25, and ranking every match just to discard the scores is what makes the
	// page query cost more than the count.
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM resources r WHERE %s AND r.id IN
		(SELECT rowid FROM resources_fts WHERE resources_fts MATCH ?)`, filterWhere)
	countArgs := append(append([]interface{}{}, filterArgs...), ftsQuery)
	var total int
	if err := db.QueryRow(countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count: %w", err)
	}

	// Fetch the page.
	//
	// The MATCH runs in a materialized CTE so the FTS index drives the scan and
	// bm25() is evaluated with the match context in hand. Writing the same logic
	// as `JOIN resources_fts ON rowid = r.id ... WHERE resources_fts MATCH ?`
	// reads identically and returns identical rows, but SQLite plans it as a
	// scan of every enabled resource with a correlated FTS lookup per row: 33ms
	// to return 2 of 1191 rows. Materializing first is 14x faster over a
	// differential sweep of every filter combination this function builds.
	//
	// MATERIALIZED is not optional. Without it SQLite is free to flatten the
	// CTE back into the join and the plan regresses to the slow form.
	pageArgs := append(append([]interface{}{ftsQuery}, filterArgs...), q.Limit, q.Offset)

	query := fmt.Sprintf(`
		WITH hits AS MATERIALIZED (
			SELECT rowid AS id, bm25(resources_fts, 10.0, 5.0, 5.0, 2.0, 1.0) AS score
			FROM resources_fts
			WHERE resources_fts MATCH ?
		)
		SELECT r.id, r.type, COALESCE(r.name,''), COALESCE(r.source,''), COALESCE(r.file_path,''),
		       COALESCE(r.category,''), COALESCE(r.tags,''),
		       COALESCE(r.description,''), '', COALESCE(r.metadata,''), r.enabled,
		       hits.score
		FROM hits
		JOIN resources r ON r.id = hits.id
		WHERE %s
		ORDER BY hits.score
		LIMIT ? OFFSET ?`, filterWhere)

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

// SearchWithFallback runs the exact query first. If that returns zero rows on
// a first-page request, it retries once with deterministic Han-to-pinyin
// context rewrite. Later pages never fall back, because the fallback rewrites
// the query into a different result set and page 2 of an exact search would
// then describe unrelated rows. q.Offset != 0 keeps that guarantee for direct
// callers; q.SkipFallback covers callers that read from the top of a ranked
// candidate list on behalf of a later page.
func SearchWithFallback(db *sql.DB, q SearchQuery) ([]SearchResult, int, FallbackSearch, error) {
	results, total, err := Search(db, q)
	if err != nil || total > 0 || q.Offset != 0 || q.SkipFallback {
		return results, total, FallbackSearch{}, err
	}
	// A query the planner cannot render is not an error here: the caller already
	// has the exact search's results, and the design mandates a plain no_match
	// rather than a failure. Returning the planner's error would turn an
	// unsearchable query into a 500.
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
	// The fallback is an optional retry on top of the exact search, which already
	// succeeded and returned nothing. A failing retry must not fail the request:
	// the degradation design says fallback failure is closed and the original
	// no_match is returned, so the error is deliberately dropped.
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
	conditions, args = appendSourceConstraints(conditions, args, "source", q.Source, q.Sources)
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
	return GetByNameInSources(db, typ, name, nil)
}

func GetByNameInSources(db *sql.DB, typ, name string, allowed []string) (*Resource, error) {
	query := `
		SELECT id, type, COALESCE(name,''), COALESCE(source,''), COALESCE(file_path,''),
		       COALESCE(category,''), COALESCE(tags,''),
		       COALESCE(description,''), COALESCE(body,''), COALESCE(metadata,'')
		FROM resources WHERE type=? AND name=? AND enabled = 1`
	args := []interface{}{typ, name}
	if clause, extra := sourceInClause("source", allowed); clause != "" {
		query += " AND " + clause
		args = append(args, extra...)
	}
	query += " LIMIT 1"
	var r Resource
	err := db.QueryRow(query, args...).Scan(
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

func appendSourceConstraints(conditions []string, args []interface{}, column, source string, allowed []string) ([]string, []interface{}) {
	if source != "" {
		conditions = append(conditions, column+" = ?")
		args = append(args, source)
	}
	if clause, extra := sourceInClause(column, allowed); clause != "" {
		conditions = append(conditions, clause)
		args = append(args, extra...)
	}
	return conditions, args
}

func sourceInClause(column string, allowed []string) (string, []interface{}) {
	if len(allowed) == 0 {
		return "", nil
	}
	placeholders := make([]string, len(allowed))
	args := make([]interface{}, len(allowed))
	for i, source := range allowed {
		placeholders[i] = "?"
		args[i] = source
	}
	return column + " IN (" + strings.Join(placeholders, ",") + ")", args
}
