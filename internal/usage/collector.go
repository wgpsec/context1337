package usage

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const SearchQueryCapacity = 10_000

var allowedTools = map[string]struct{}{
	"search_security":     {},
	"get_security_detail": {},
	"read_security_file":  {},
	"search_skill":        {},
	"search_dicts":        {},
	"search_payload":      {},
	"list_skills":         {},
	"list_dicts":          {},
	"list_payloads":       {},
	"get_skill":           {},
	"get_dict":            {},
	"get_payload":         {},
	"search_vuln":         {},
	"list_vulns":          {},
	"get_vuln":            {},
}

var (
	durationBucketNames = []string{"lt_10", "lt_50", "lt_250", "lt_1000", "gte_1000"}
	byteBucketNames     = []string{"lt_1k", "lt_10k", "lt_100k", "gte_100k"}
	clientFamilies      = []string{"pojun-agent", "codex", "claude", "python", "other"}
)

type Snapshot struct {
	StartedAt   time.Time     `json:"started_at"`
	GeneratedAt time.Time     `json:"generated_at"`
	MCPHTTP     HTTPMetrics   `json:"mcp_http"`
	MCP         MCPMetrics    `json:"mcp"`
	Tools       ToolMetrics   `json:"tools"`
	Search      SearchMetrics `json:"search"`
}

type HTTPMetrics struct {
	RequestsTotal          uint64            `json:"requests_total"`
	RequestsByStatusClass  map[string]uint64 `json:"requests_by_status_class"`
	RequestsByClientFamily map[string]uint64 `json:"requests_by_client_family"`
	DurationMS             map[string]uint64 `json:"duration_ms"`
	ResponseBytes          map[string]uint64 `json:"response_bytes"`
	ActiveRequests         int64             `json:"active_requests"`
}

type MCPMetrics struct {
	ActiveSessions int64 `json:"active_sessions"`
}

type ToolMetrics struct {
	CallsTotal    uint64            `json:"calls_total"`
	CallsByName   map[string]uint64 `json:"calls_by_name"`
	CallsByStatus map[string]uint64 `json:"calls_by_status"`
	DurationMS    map[string]uint64 `json:"duration_ms"`
	ResponseBytes map[string]uint64 `json:"response_bytes"`
}

type SearchMetrics struct {
	QueriesTotal        uint64              `json:"queries_total"`
	MatchedTotal        uint64              `json:"matched_total"`
	ZeroResultTotal     uint64              `json:"zero_result_total"`
	ErrorTotal          uint64              `json:"error_total"`
	ResultCount         map[string]uint64   `json:"result_count"`
	QueryCapacity       int                 `json:"query_capacity"`
	TrackedQueries      int                 `json:"tracked_queries"`
	DroppedQueriesTotal uint64              `json:"dropped_queries_total"`
	Queries             []SearchQueryMetric `json:"queries"`
	ZeroResultQueries   []SearchQueryMetric `json:"zero_result_queries"`
}

type SearchQueryMetric struct {
	Query        string `json:"query"`
	ResourceType string `json:"resource_type,omitempty"`
	Category     string `json:"category,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Product      string `json:"product,omitempty"`
	Calls        uint64 `json:"calls"`
	Matched      uint64 `json:"matched"`
	ZeroResults  uint64 `json:"zero_results"`
	Errors       uint64 `json:"errors"`
	ResultsTotal uint64 `json:"results_total"`
}

type SearchObservation struct {
	Query        string
	ResourceType string
	Category     string
	Severity     string
	Product      string
	ResultCount  int
	Failed       bool
}

type searchQueryKey struct {
	query        string
	resourceType string
	category     string
	severity     string
	product      string
}

type searchCounters struct {
	queriesTotal        uint64
	matchedTotal        uint64
	zeroResultTotal     uint64
	errorTotal          uint64
	resultCount         map[string]uint64
	droppedQueriesTotal uint64
	queries             map[searchQueryKey]*SearchQueryMetric
}

type Collector struct {
	mu                     sync.RWMutex
	startedAt              time.Time
	httpMetrics            HTTPMetrics
	toolMetrics            ToolMetrics
	searchMetrics          searchCounters
	activeSessionsProvider func() int64
}

func NewCollector() *Collector {
	return &Collector{
		startedAt: time.Now().UTC(),
		httpMetrics: HTTPMetrics{
			RequestsByStatusClass:  zeroMap([]string{"1xx", "2xx", "3xx", "4xx", "5xx", "other"}),
			RequestsByClientFamily: zeroMap(clientFamilies),
			DurationMS:             zeroMap(durationBucketNames),
			ResponseBytes:          zeroMap(byteBucketNames),
		},
		toolMetrics: ToolMetrics{
			CallsByName:   zeroToolMap(),
			CallsByStatus: zeroMap([]string{"success", "error"}),
			DurationMS:    zeroMap(durationBucketNames),
			ResponseBytes: zeroMap(byteBucketNames),
		},
		searchMetrics: searchCounters{
			resultCount: zeroMap([]string{"zero", "one", "lt_10", "lt_100", "gte_100"}),
			queries:     make(map[searchQueryKey]*SearchQueryMetric, SearchQueryCapacity),
		},
	}
}

func (c *Collector) RecordSearch(observation SearchObservation) {
	if c == nil {
		return
	}
	key := searchQueryKey{
		query:        normalizeSearchValue(observation.Query),
		resourceType: normalizeSearchValue(observation.ResourceType),
		category:     normalizeSearchValue(observation.Category),
		severity:     normalizeSearchValue(observation.Severity),
		product:      normalizeSearchValue(observation.Product),
	}
	if key.query == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.searchMetrics.queriesTotal++
	if observation.Failed {
		c.searchMetrics.errorTotal++
	} else if observation.ResultCount <= 0 {
		c.searchMetrics.zeroResultTotal++
		c.searchMetrics.resultCount["zero"]++
	} else {
		c.searchMetrics.matchedTotal++
		c.searchMetrics.resultCount[resultCountBucket(observation.ResultCount)]++
	}

	query, exists := c.searchMetrics.queries[key]
	if !exists {
		if len(c.searchMetrics.queries) >= SearchQueryCapacity {
			c.searchMetrics.droppedQueriesTotal++
			return
		}
		query = &SearchQueryMetric{
			Query:        key.query,
			ResourceType: key.resourceType,
			Category:     key.category,
			Severity:     key.severity,
			Product:      key.product,
		}
		c.searchMetrics.queries[key] = query
	}
	query.Calls++
	if observation.Failed {
		query.Errors++
	} else if observation.ResultCount <= 0 {
		query.ZeroResults++
	} else {
		query.Matched++
		query.ResultsTotal += uint64(observation.ResultCount)
	}
}

func (c *Collector) beginHTTPRequest() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.httpMetrics.ActiveRequests++
	c.mu.Unlock()
}

func (c *Collector) finishHTTPRequest(statusCode int, clientFamily string, duration time.Duration, responseBytes int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.httpMetrics.ActiveRequests--
	c.httpMetrics.RequestsTotal++
	c.httpMetrics.RequestsByStatusClass[statusClass(statusCode)]++
	c.httpMetrics.RequestsByClientFamily[clientFamily]++
	c.httpMetrics.DurationMS[durationBucket(duration)]++
	c.httpMetrics.ResponseBytes[byteBucket(responseBytes)]++
}

func (c *Collector) RecordTool(name string, success bool, duration time.Duration, responseBytes int) {
	if c == nil {
		return
	}
	if _, ok := allowedTools[name]; !ok {
		name = "other"
	}
	status := "error"
	if success {
		status = "success"
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.toolMetrics.CallsTotal++
	c.toolMetrics.CallsByName[name]++
	c.toolMetrics.CallsByStatus[status]++
	c.toolMetrics.DurationMS[durationBucket(duration)]++
	c.toolMetrics.ResponseBytes[byteBucket(responseBytes)]++
}

func (c *Collector) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{GeneratedAt: time.Now().UTC()}
	}
	c.mu.RLock()
	snapshot := Snapshot{
		StartedAt:   c.startedAt,
		GeneratedAt: time.Now().UTC(),
		MCPHTTP:     copyHTTPMetrics(c.httpMetrics),
		Tools:       copyToolMetrics(c.toolMetrics),
		Search:      copySearchMetrics(c.searchMetrics),
	}
	provider := c.activeSessionsProvider
	c.mu.RUnlock()
	sortSearchQueries(snapshot.Search.Queries, false)
	sortSearchQueries(snapshot.Search.ZeroResultQueries, true)
	if provider != nil {
		snapshot.MCP.ActiveSessions = provider()
	}
	return snapshot
}

func normalizeSearchValue(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func resultCountBucket(count int) string {
	switch {
	case count <= 0:
		return "zero"
	case count == 1:
		return "one"
	case count < 10:
		return "lt_10"
	case count < 100:
		return "lt_100"
	default:
		return "gte_100"
	}
}

func (c *Collector) SetActiveSessionsProvider(provider func() int64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.activeSessionsProvider = provider
	c.mu.Unlock()
}

func zeroMap(keys []string) map[string]uint64 {
	values := make(map[string]uint64, len(keys))
	for _, key := range keys {
		values[key] = 0
	}
	return values
}

func zeroToolMap() map[string]uint64 {
	values := make(map[string]uint64, len(allowedTools)+1)
	for name := range allowedTools {
		values[name] = 0
	}
	values["other"] = 0
	return values
}

func durationBucket(duration time.Duration) string {
	milliseconds := duration.Milliseconds()
	switch {
	case milliseconds < 10:
		return "lt_10"
	case milliseconds < 50:
		return "lt_50"
	case milliseconds < 250:
		return "lt_250"
	case milliseconds < 1000:
		return "lt_1000"
	default:
		return "gte_1000"
	}
}

func byteBucket(size int) string {
	switch {
	case size < 1024:
		return "lt_1k"
	case size < 10*1024:
		return "lt_10k"
	case size < 100*1024:
		return "lt_100k"
	default:
		return "gte_100k"
	}
}

func statusClass(statusCode int) string {
	if statusCode < 100 || statusCode > 599 {
		return "other"
	}
	return string(rune('0'+statusCode/100)) + "xx"
}

func copyMap(source map[string]uint64) map[string]uint64 {
	destination := make(map[string]uint64, len(source))
	for key, value := range source {
		destination[key] = value
	}
	return destination
}

func copyHTTPMetrics(metrics HTTPMetrics) HTTPMetrics {
	metrics.RequestsByStatusClass = copyMap(metrics.RequestsByStatusClass)
	metrics.RequestsByClientFamily = copyMap(metrics.RequestsByClientFamily)
	metrics.DurationMS = copyMap(metrics.DurationMS)
	metrics.ResponseBytes = copyMap(metrics.ResponseBytes)
	return metrics
}

func copyToolMetrics(metrics ToolMetrics) ToolMetrics {
	metrics.CallsByName = copyMap(metrics.CallsByName)
	metrics.CallsByStatus = copyMap(metrics.CallsByStatus)
	metrics.DurationMS = copyMap(metrics.DurationMS)
	metrics.ResponseBytes = copyMap(metrics.ResponseBytes)
	return metrics
}

func copySearchMetrics(metrics searchCounters) SearchMetrics {
	queries := make([]SearchQueryMetric, 0, len(metrics.queries))
	zeroResultQueries := make([]SearchQueryMetric, 0)
	for _, query := range metrics.queries {
		copy := *query
		queries = append(queries, copy)
		if copy.ZeroResults > 0 {
			zeroResultQueries = append(zeroResultQueries, copy)
		}
	}
	return SearchMetrics{
		QueriesTotal:        metrics.queriesTotal,
		MatchedTotal:        metrics.matchedTotal,
		ZeroResultTotal:     metrics.zeroResultTotal,
		ErrorTotal:          metrics.errorTotal,
		ResultCount:         copyMap(metrics.resultCount),
		QueryCapacity:       SearchQueryCapacity,
		TrackedQueries:      len(metrics.queries),
		DroppedQueriesTotal: metrics.droppedQueriesTotal,
		Queries:             queries,
		ZeroResultQueries:   zeroResultQueries,
	}
}

func sortSearchQueries(queries []SearchQueryMetric, zeroResultsFirst bool) {
	sort.Slice(queries, func(i, j int) bool {
		left, right := queries[i], queries[j]
		if zeroResultsFirst && left.ZeroResults != right.ZeroResults {
			return left.ZeroResults > right.ZeroResults
		}
		if left.Calls != right.Calls {
			return left.Calls > right.Calls
		}
		if left.Query != right.Query {
			return left.Query < right.Query
		}
		if left.ResourceType != right.ResourceType {
			return left.ResourceType < right.ResourceType
		}
		if left.Category != right.Category {
			return left.Category < right.Category
		}
		if left.Severity != right.Severity {
			return left.Severity < right.Severity
		}
		return left.Product < right.Product
	})
}
