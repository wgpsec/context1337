package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wgpsec/context1337/internal/search"
	"github.com/wgpsec/context1337/internal/storage"
	"github.com/wgpsec/context1337/internal/usage"
)

// Service holds shared dependencies for all MCP handlers.
type Service struct {
	DB      *sql.DB
	DataDir string
	Usage   *usage.Collector
}

// SkillReference represents a named reference file bundled with a skill.
type SkillReference struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

func extractVulnMeta(metadata string) (severity, product, vendor, versionAffected, fingerprint string) {
	if metadata == "" {
		return
	}
	var meta map[string]string
	json.Unmarshal([]byte(metadata), &meta)
	return meta["severity"], meta["product"], meta["vendor"], meta["version_affected"], meta["fingerprint"]
}

func extractSizeMeta(metadata, resourceType string) (bodyLines, refCount, lines int) {
	if metadata == "" {
		return
	}
	dec := json.NewDecoder(strings.NewReader(metadata))
	dec.UseNumber()
	var meta map[string]json.Number
	if err := dec.Decode(&meta); err != nil {
		return
	}
	toInt := func(n json.Number) int {
		v, _ := n.Int64()
		return int(v)
	}
	switch resourceType {
	case "skill":
		return toInt(meta["body_lines"]), toInt(meta["ref_count"]), 0
	case "dict", "payload":
		return 0, 0, toInt(meta["lines"])
	}
	return
}

// splitSkillBody extracts frontmatter and body from a SKILL.md file content.
func splitSkillBody(content string) (string, string, error) {
	if !strings.HasPrefix(content, "---") {
		return "", content, nil
	}
	rest := content[3:]
	idx := strings.Index(rest, "\n---")
	if idx < 0 {
		return "", content, fmt.Errorf("unclosed frontmatter")
	}
	return strings.TrimSpace(rest[:idx]), rest[idx+4:], nil
}

// relevanceCutoff is the minimum fraction of the best BM25 score a result
// must reach to be included. FTS5 bm25() returns negative values (more
// negative = more relevant). 0.2 means keep results at least 20% as strong
// as the best hit, trimming the long tail of barely-matching documents.
const relevanceCutoff = 0.2

// trimByRelevance drops results whose BM25 score falls below relevanceCutoff
// of the globally best raw score while preserving the canonical rank order.
func trimByRelevance(results []search.SearchResult) []search.SearchResult {
	if len(results) <= 1 {
		return results
	}
	best := results[0].Score
	if best >= 0 {
		return results // guard: unexpected non-negative scores
	}
	for _, result := range results[1:] {
		if result.Score >= 0 {
			return results // guard: unexpected non-negative scores
		}
		if result.Score < best {
			best = result.Score
		}
	}
	threshold := best * relevanceCutoff
	trimmed := make([]search.SearchResult, 0, len(results))
	for _, result := range results {
		if result.Score <= threshold {
			trimmed = append(trimmed, result)
		}
	}
	return trimmed
}

// diversifyByType re-orders results so that no single type dominates the top
// positions. It uses round-robin across types, preserving BM25 rank within
// each type bucket. This ensures that a cross-type search for "SQL injection"
// surfaces skills alongside payloads, even when payloads score slightly higher
// due to shorter document length and tag density.
//
// Only applied when the caller did NOT specify a type filter.
func diversifyByType(results []search.SearchResult) []search.SearchResult {
	if len(results) <= 1 {
		return results
	}

	// Split results into per-type buckets, preserving order.
	bucketOrder := []string{} // insertion-ordered type keys
	buckets := map[string][]search.SearchResult{}
	for _, r := range results {
		if _, exists := buckets[r.Type]; !exists {
			bucketOrder = append(bucketOrder, r.Type)
		}
		buckets[r.Type] = append(buckets[r.Type], r)
	}

	if len(bucketOrder) <= 1 {
		return results // single type, nothing to diversify
	}

	// Round-robin merge: pick one from each type in turn.
	out := make([]search.SearchResult, 0, len(results))
	idx := make(map[string]int, len(bucketOrder))
	for len(out) < len(results) {
		progress := false
		for _, typ := range bucketOrder {
			i := idx[typ]
			if i < len(buckets[typ]) {
				out = append(out, buckets[typ][i])
				idx[typ] = i + 1
				progress = true
			}
		}
		if !progress {
			break
		}
	}
	return out
}

// --- search ---

type SearchInput struct {
	Query    string `json:"query,omitempty"    jsonschema:"Search keywords (omit to list all)"`
	Type     string `json:"type,omitempty"     jsonschema:"Filter by type: skill|dict|payload|vuln (omit to search all non-vuln types)"`
	Category string `json:"category,omitempty" jsonschema:"Filter by category"`
	Severity string `json:"severity,omitempty" jsonschema:"Filter by severity (vuln only): CRITICAL|HIGH|MEDIUM|LOW"`
	Product  string `json:"product,omitempty"  jsonschema:"Filter by product name (vuln only)"`
	Offset   int    `json:"offset,omitempty"   jsonschema:"Pagination offset (default 0)"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results to return (default 10). Increase only when the caller explicitly needs more."`
}

type ResourceSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Source      string `json:"source"`
	Tags        string `json:"tags,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Product     string `json:"product,omitempty"`
	Vendor      string `json:"vendor,omitempty"`
	BodyLines   int    `json:"body_lines,omitempty"`
	RefCount    int    `json:"ref_count,omitempty"`
	Lines       int    `json:"lines,omitempty"`
}

type SearchResult struct {
	SearchVersion       string             `json:"search_version"`
	Status              string             `json:"status"`
	Total               int                `json:"total"`
	Offset              int                `json:"offset"`
	Limit               int                `json:"limit"`
	Items               []ResourceSummary  `json:"items"`
	Hint                string             `json:"hint,omitempty"`
	RetryQueries        []SearchRetryQuery `json:"retry_queries,omitempty"`
	Resolution          *SearchResolution  `json:"resolution,omitempty"`
	AttemptedStrategies []string           `json:"attempted_strategies,omitempty"`
	RetryGuidance       []SearchGuidance   `json:"retry_guidance,omitempty"`
}

type SearchGuidance struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
}

type SearchTransliteration struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type SearchResolution struct {
	Mode             string                  `json:"mode"`
	OriginalQuery    string                  `json:"original_query"`
	EffectiveQuery   string                  `json:"effective_query"`
	Transliterations []SearchTransliteration `json:"transliterations"`
	Reason           string                  `json:"reason"`
}

type SearchRetryQuery struct {
	Query string `json:"query"`
	Type  string `json:"type,omitempty"`
}

func resourceToSummary(r search.Resource) ResourceSummary {
	s := ResourceSummary{
		ID:   search.StableID(r),
		Name: r.Name, Type: r.Type, Description: r.Description,
		Category: r.Category, Source: r.Source,
		Tags: r.Tags,
	}
	if r.Type == "vuln" {
		s.Severity, s.Product, s.Vendor, _, _ = extractVulnMeta(r.Metadata)
	}
	if r.Type == "skill" || r.Type == "dict" || r.Type == "payload" {
		s.BodyLines, s.RefCount, s.Lines = extractSizeMeta(r.Metadata, r.Type)
	}
	return s
}

func searchHint(query, typ string) string {
	if typ != "" {
		return fmt.Sprintf(
			"no results for %q with type=%s; retry without the type filter to search across all resource types",
			query, typ,
		)
	}
	return fmt.Sprintf(
		"no results for %q; try broader or alternative keywords. Vulnerabilities are excluded by default; retry with type=\"vuln\" for CVE, product vulnerability, endpoint, or PoC searches",
		query,
	)
}

func (s *Service) Search(ctx context.Context, in SearchInput) (out *SearchResult, err error) {
	if strings.TrimSpace(in.Query) != "" {
		defer func() {
			resultCount := 0
			rejectedComplexity := false
			transliterated := false
			var transliterations []usage.SearchTransliteration
			if out != nil {
				resultCount = out.Total
				rejectedComplexity = out.Status == "query_too_complex"
				transliterated = out.Resolution != nil && out.Resolution.Mode == "transliterated"
				if transliterated {
					transliterations = make([]usage.SearchTransliteration, len(out.Resolution.Transliterations))
					for index, mapping := range out.Resolution.Transliterations {
						transliterations[index] = usage.SearchTransliteration{From: mapping.From, To: mapping.To}
					}
				}
			}
			s.Usage.RecordSearch(usage.SearchObservation{
				Query:              in.Query,
				ResourceType:       in.Type,
				Category:           in.Category,
				Severity:           in.Severity,
				Product:            in.Product,
				ResultCount:        resultCount,
				Failed:             err != nil,
				RejectedComplexity: rejectedComplexity,
				Transliterated:     transliterated,
				Transliterations:   transliterations,
			})
		}()
	}
	if in.Limit <= 0 {
		if in.Type == "vuln" {
			in.Limit = 50
		} else {
			in.Limit = 10
		}
	}

	// Non-empty query -> FTS5 search
	if in.Query != "" {
		// When searching across types, fetch extra results so diversify
		// has enough material from each type to fill the final page.
		fetchLimit := in.Limit
		if in.Type == "" {
			fetchLimit = in.Limit * 3
		}
		results, total, fallback, err := search.SearchWithFallback(s.DB, search.SearchQuery{
			Query: in.Query, Type: in.Type, Category: in.Category,
			Severity: in.Severity, Product: in.Product,
			Offset: in.Offset, Limit: fetchLimit,
		})
		if err != nil {
			var complexityError *search.QueryComplexityError
			if errors.As(err, &complexityError) {
				retries := search.BuildFocusedRetryQueries(complexityError.Groups, in.Type)
				responseRetries := make([]SearchRetryQuery, len(retries))
				for index, retry := range retries {
					responseRetries[index] = SearchRetryQuery{Query: retry.Query, Type: retry.Type}
				}
				return &SearchResult{
					SearchVersion: search.SearchContractVersion,
					Status:        "query_too_complex",
					Offset:        in.Offset,
					Limit:         in.Limit,
					Items:         []ResourceSummary{},
					Hint:          complexityError.Error() + "; split the request into focused searches",
					RetryQueries:  responseRetries,
				}, nil
			}
			return nil, err
		}
		present := func(inResults []search.SearchResult) []search.SearchResult {
			inResults = trimByRelevance(inResults)
			if in.Type == "" {
				inResults = diversifyByType(inResults)
			}
			if len(inResults) > in.Limit {
				inResults = inResults[:in.Limit]
			}
			return inResults
		}
		summarize := func(inResults []search.SearchResult) []ResourceSummary {
			items := make([]ResourceSummary, len(inResults))
			for i, result := range inResults {
				items[i] = resourceToSummary(result.Resource)
			}
			return items
		}
		if fallback.Used {
			mappings := make([]SearchTransliteration, len(fallback.Transliterations))
			for index, mapping := range fallback.Transliterations {
				mappings[index] = SearchTransliteration{From: mapping.From, To: mapping.To}
			}
			return &SearchResult{
				SearchVersion: search.SearchContractVersion,
				Status:        "matched",
				Total:         total,
				Offset:        in.Offset,
				Limit:         in.Limit,
				Items:         summarize(present(results)),
				Hint:          "Exact query returned no results. Showing results after deterministic Chinese-to-pinyin transliteration.",
				Resolution: &SearchResolution{
					Mode: "transliterated", OriginalQuery: in.Query, EffectiveQuery: fallback.Query,
					Transliterations: mappings, Reason: "chinese_context_transliteration",
				},
				AttemptedStrategies: []string{"exact", "pinyin"},
			}, nil
		}
		results = present(results)
		items := summarize(results)
		// If cutoff reduced this page, cap total so the caller does not
		// paginate into low-relevance results.
		if len(results) < in.Limit {
			total = in.Offset + len(results)
		}
		out = &SearchResult{
			SearchVersion: search.SearchContractVersion,
			Status:        "matched",
			Total:         total, Offset: in.Offset, Limit: in.Limit, Items: items,
		}
		if total == 0 {
			out.Status = "no_match"
			out.Hint = searchHint(in.Query, in.Type)
			out.AttemptedStrategies = []string{"exact"}
			if fallback.Attempted {
				out.AttemptedStrategies = append(out.AttemptedStrategies, "pinyin")
				out.Hint = "Exact and pinyin searches returned no results. Translate Chinese product or component terms to English, or remove non-essential keywords and retry. " + out.Hint
				out.RetryGuidance = append(out.RetryGuidance, SearchGuidance{
					Action: "translate_to_english", Reason: "chinese_context_not_found",
				})
			}
			out.RetryGuidance = append(out.RetryGuidance, SearchGuidance{
				Action: "reduce_keywords", Reason: "focused_query_returned_no_results",
			})
			plan, planErr := search.PlanQuery(in.Query)
			if planErr == nil {
				retries := search.BuildMultiTopicRetryQueries(plan.Groups, in.Type)
				if len(retries) > 0 {
					out.RetryQueries = make([]SearchRetryQuery, len(retries))
					for index, retry := range retries {
						out.RetryQueries[index] = SearchRetryQuery{Query: retry.Query, Type: retry.Type}
					}
					out.Hint += "; split this multi-topic request into the focused retry queries"
				}
			}
		}
		return out, nil
	}

	// Empty query -> list
	result, err := search.ListByType(s.DB, search.ListQuery{
		Type: in.Type, Category: in.Category,
		Severity: in.Severity, Product: in.Product,
		Offset: in.Offset, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	items := make([]ResourceSummary, len(result.Items))
	for i, r := range result.Items {
		items[i] = resourceToSummary(r)
	}
	status := "matched"
	if result.Total == 0 {
		status = "no_match"
	}
	return &SearchResult{
		SearchVersion: search.SearchContractVersion,
		Status:        status,
		Total:         result.Total, Offset: in.Offset, Limit: in.Limit, Items: items,
	}, nil
}

// --- get ---

type GetInput struct {
	ID        string `json:"id,omitempty"         jsonschema:"Stable resource ID from search results"`
	Name      string `json:"name,omitempty"       jsonschema:"Resource name (from search results)"`
	Type      string `json:"type,omitempty"       jsonschema:"Resource type: skill|vuln"`
	Depth     string `json:"depth,omitempty"      jsonschema:"Loading depth. Skill: metadata|summary|full (default summary). Vuln: brief|full (default brief). full includes references (skill) or PoC (vuln)."`
	RefOffset int    `json:"ref_offset,omitempty" jsonschema:"Reference pagination offset (default 0, skill depth=full only)"`
	RefLimit  int    `json:"ref_limit,omitempty"  jsonschema:"Max references to include (default 3, skill depth=full only)"`
}

type GetResult struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Type            string           `json:"type"`
	Description     string           `json:"description"`
	Category        string           `json:"category"`
	Source          string           `json:"source"`
	Tags            string           `json:"tags,omitempty"`
	Body            string           `json:"body,omitempty"`
	References      []SkillReference `json:"references,omitempty"`
	RefTotal        int              `json:"ref_total,omitempty"`
	Severity        string           `json:"severity,omitempty"`
	Product         string           `json:"product,omitempty"`
	Vendor          string           `json:"vendor,omitempty"`
	VersionAffected string           `json:"version_affected,omitempty"`
	Fingerprint     string           `json:"fingerprint,omitempty"`
}

func (s *Service) resolveGetResource(in GetInput) (*search.Resource, error) {
	if in.ID == "" {
		if in.Type != "skill" && in.Type != "vuln" {
			return nil, fmt.Errorf("type must be skill or vuln (use read_security_file for dict/payload)")
		}

		r, err := search.GetByName(s.DB, in.Type, in.Name)
		if err != nil {
			return nil, err
		}
		if r == nil {
			return nil, fmt.Errorf(
				"%s %q not found; try search_security with broader keywords, or omit query to list all %ss",
				in.Type, in.Name, in.Type,
			)
		}
		return r, nil
	}

	_, idType, _, err := search.ParseStableID(in.ID)
	if err != nil {
		return nil, err
	}
	if idType != "skill" && idType != "vuln" {
		return nil, fmt.Errorf("resource ID %q refers to type %s; use read_security_file for dict/payload", in.ID, idType)
	}

	r, err := search.GetByStableID(s.DB, in.ID)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("resource ID %q not found; try search_security to get a current stable id", in.ID)
	}
	if in.Type != "" && in.Type != r.Type {
		return nil, fmt.Errorf("type %q conflicts with resource ID type %q", in.Type, r.Type)
	}
	if in.Name != "" && in.Name != r.Name {
		return nil, fmt.Errorf("name %q conflicts with resource ID name %q", in.Name, r.Name)
	}
	return r, nil
}

func (s *Service) Get(ctx context.Context, in GetInput) (*GetResult, error) {
	r, err := s.resolveGetResource(in)
	if err != nil {
		return nil, err
	}

	result := &GetResult{
		ID:   search.StableID(*r),
		Name: r.Name, Type: r.Type, Description: r.Description,
		Category: r.Category, Source: r.Source,
		Tags: r.Tags,
	}

	switch r.Type {
	case "skill":
		if in.Depth == "" {
			in.Depth = "summary"
		}
		switch in.Depth {
		case "metadata":
			// No body
		case "summary":
			// Read original SKILL.md body from disk (without tokenized refs)
			if data, err := os.ReadFile(r.FilePath); err == nil {
				if _, rawBody, fmErr := splitSkillBody(string(data)); fmErr == nil {
					result.Body = strings.TrimSpace(rawBody)
				}
			} else {
				// Fallback: try stripping refs from DB body
				body := r.Body
				if idx := strings.Index(body, "\n\n---\n## [ref] "); idx >= 0 {
					body = body[:idx]
				}
				result.Body = body
			}
			// Include ref_total so caller knows references exist
			skillDir := filepath.Dir(r.FilePath)
			if refs, err := storage.ReadReferences(skillDir); err == nil && len(refs) > 0 {
				result.RefTotal = len(refs)
			}
		case "full":
			// Read original SKILL.md body from disk (without concatenated refs)
			skillDir := filepath.Dir(r.FilePath)
			if data, err := os.ReadFile(r.FilePath); err == nil {
				if _, rawBody, fmErr := splitSkillBody(string(data)); fmErr == nil {
					result.Body = strings.TrimSpace(rawBody)
				}
			} else {
				// Fallback for custom skills with no on-disk file: use DB body
				body := r.Body
				if idx := strings.Index(body, "\n\n---\n## [ref] "); idx >= 0 {
					body = body[:idx]
				}
				result.Body = body
			}
			// Load references with pagination
			refs, err := storage.ReadReferences(skillDir)
			if err == nil && len(refs) > 0 {
				result.RefTotal = len(refs)
				start := in.RefOffset
				if start > len(refs) {
					start = len(refs)
				}
				limit := in.RefLimit
				if limit <= 0 {
					limit = 3
				}
				end := start + limit
				if end > len(refs) {
					end = len(refs)
				}
				result.References = make([]SkillReference, end-start)
				for i, ref := range refs[start:end] {
					result.References[i] = SkillReference{Name: ref.Name, Content: ref.Content}
				}
			}
		}
	case "vuln":
		if in.Depth == "" {
			in.Depth = "brief"
		}
		severity, product, vendor, versionAffected, fingerprint := extractVulnMeta(r.Metadata)
		result.Severity = severity
		result.Product = product
		result.Vendor = vendor
		result.VersionAffected = versionAffected
		switch in.Depth {
		case "brief":
			// No body — structured fields + description only
		case "full":
			result.Body = r.Body
			result.Fingerprint = fingerprint
			// For nuclei templates, append raw YAML so LLM gets HTTP requests/payloads
			if r.Source == "nuclei" && r.FilePath != "" {
				if data, err := os.ReadFile(r.FilePath); err == nil {
					result.Body = r.Body + "\n\n---\n# Nuclei Template\n```yaml\n" + string(data) + "\n```"
				}
			}
		}
	}

	return result, nil
}
