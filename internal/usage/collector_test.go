package usage

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCollectorRecordsBoundedToolMetrics(t *testing.T) {
	collector := NewCollector()
	collector.RecordTool("search_security", true, 8*time.Millisecond, 512)
	collector.RecordTool("unknown-secret-tool", false, 2*time.Second, 120_000)

	snapshot := collector.Snapshot()
	if snapshot.Tools.CallsTotal != 2 {
		t.Fatalf("calls total = %d, want 2", snapshot.Tools.CallsTotal)
	}
	if snapshot.Tools.CallsByName["search_security"] != 1 {
		t.Errorf("search_security calls = %d, want 1", snapshot.Tools.CallsByName["search_security"])
	}
	if snapshot.Tools.CallsByName["other"] != 1 {
		t.Errorf("other calls = %d, want 1", snapshot.Tools.CallsByName["other"])
	}
	if snapshot.Tools.CallsByStatus["success"] != 1 || snapshot.Tools.CallsByStatus["error"] != 1 {
		t.Errorf("calls by status = %#v, want one success and one error", snapshot.Tools.CallsByStatus)
	}
	if snapshot.Tools.DurationMS["lt_10"] != 1 || snapshot.Tools.DurationMS["gte_1000"] != 1 {
		t.Errorf("duration buckets = %#v, want lt_10=1 and gte_1000=1", snapshot.Tools.DurationMS)
	}
	if snapshot.Tools.ResponseBytes["lt_1k"] != 1 || snapshot.Tools.ResponseBytes["gte_100k"] != 1 {
		t.Errorf("response byte buckets = %#v, want lt_1k=1 and gte_100k=1", snapshot.Tools.ResponseBytes)
	}

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "unknown-secret-tool") {
		t.Fatalf("snapshot leaks unknown tool name: %s", encoded)
	}
}

func TestCollectorRecordsExactSearchQueriesAndZeroResults(t *testing.T) {
	collector := NewCollector()
	collector.RecordSearch(SearchObservation{
		Query: "  JWT   Algorithm Confusion ", ResourceType: "skill", ResultCount: 3,
	})
	collector.RecordSearch(SearchObservation{
		Query: "jwt algorithm confusion", ResourceType: "skill", ResultCount: 0,
	})
	collector.RecordSearch(SearchObservation{
		Query: "Exchange Privilege Escalation", ResourceType: "skill", ResultCount: 0,
	})
	collector.RecordSearch(SearchObservation{
		Query: "database unavailable query", ResourceType: "vuln", Failed: true,
	})

	snapshot := collector.Snapshot()
	if snapshot.Search.QueriesTotal != 4 {
		t.Fatalf("queries total = %d, want 4", snapshot.Search.QueriesTotal)
	}
	if snapshot.Search.MatchedTotal != 1 || snapshot.Search.ZeroResultTotal != 2 || snapshot.Search.ErrorTotal != 1 {
		t.Errorf("search totals = %#v, want matched=1 zero=2 error=1", snapshot.Search)
	}
	if snapshot.Search.TrackedQueries != 3 {
		t.Errorf("tracked queries = %d, want 3", snapshot.Search.TrackedQueries)
	}

	query := findSearchQuery(t, snapshot.Search.Queries, "jwt algorithm confusion", "skill")
	if query.Calls != 2 || query.Matched != 1 || query.ZeroResults != 1 || query.ResultsTotal != 3 {
		t.Errorf("JWT query = %#v, want calls=2 matched=1 zero=1 results=3", query)
	}
	missing := findSearchQuery(t, snapshot.Search.ZeroResultQueries, "exchange privilege escalation", "skill")
	if missing.Calls != 1 || missing.ZeroResults != 1 {
		t.Errorf("missing query = %#v, want one zero-result call", missing)
	}
	if snapshot.Search.ResultCount["zero"] != 2 || snapshot.Search.ResultCount["lt_10"] != 1 {
		t.Errorf("result count buckets = %#v, want zero=2 and lt_10=1", snapshot.Search.ResultCount)
	}
}

func TestCollectorBoundsDistinctSearchQueriesAndReportsDrops(t *testing.T) {
	collector := NewCollector()
	for i := 0; i <= SearchQueryCapacity; i++ {
		collector.RecordSearch(SearchObservation{
			Query:       fmt.Sprintf("query-%05d", i),
			ResultCount: 1,
		})
	}

	snapshot := collector.Snapshot()
	if snapshot.Search.QueriesTotal != SearchQueryCapacity+1 {
		t.Errorf("queries total = %d, want %d", snapshot.Search.QueriesTotal, SearchQueryCapacity+1)
	}
	if snapshot.Search.TrackedQueries != SearchQueryCapacity {
		t.Errorf("tracked queries = %d, want %d", snapshot.Search.TrackedQueries, SearchQueryCapacity)
	}
	if snapshot.Search.DroppedQueriesTotal != 1 {
		t.Errorf("dropped queries = %d, want 1", snapshot.Search.DroppedQueriesTotal)
	}
}

func findSearchQuery(t *testing.T, queries []SearchQueryMetric, query, resourceType string) SearchQueryMetric {
	t.Helper()
	for _, candidate := range queries {
		if candidate.Query == query && candidate.ResourceType == resourceType {
			return candidate
		}
	}
	t.Fatalf("query %q type %q not found in %#v", query, resourceType, queries)
	return SearchQueryMetric{}
}

func TestWrapMCPRecordsNormalizedHTTPMetricsAndPreservesStreaming(t *testing.T) {
	collector := NewCollector()
	started := make(chan struct{})
	release := make(chan struct{})
	handler := collector.WrapMCP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, ok := w.(http.Flusher); !ok {
			t.Error("instrumented response writer does not implement http.Flusher")
		}
		close(started)
		<-release
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(strings.Repeat("x", 1500)))
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp?secret=query-value", nil)
	req.Header.Set("User-Agent", "claude-cli/2.1.119 secret-user-agent")
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.ServeHTTP(recorder, req)
	}()
	<-started

	if active := collector.Snapshot().MCPHTTP.ActiveRequests; active != 1 {
		t.Fatalf("active requests = %d, want 1", active)
	}
	close(release)
	<-done

	snapshot := collector.Snapshot()
	if snapshot.MCPHTTP.ActiveRequests != 0 {
		t.Errorf("active requests = %d after completion, want 0", snapshot.MCPHTTP.ActiveRequests)
	}
	if snapshot.MCPHTTP.RequestsTotal != 1 {
		t.Errorf("requests total = %d, want 1", snapshot.MCPHTTP.RequestsTotal)
	}
	if snapshot.MCPHTTP.RequestsByStatusClass["5xx"] != 1 {
		t.Errorf("status classes = %#v, want 5xx=1", snapshot.MCPHTTP.RequestsByStatusClass)
	}
	if snapshot.MCPHTTP.RequestsByClientFamily["claude"] != 1 {
		t.Errorf("client families = %#v, want claude=1", snapshot.MCPHTTP.RequestsByClientFamily)
	}
	if snapshot.MCPHTTP.ResponseBytes["lt_10k"] != 1 {
		t.Errorf("response byte buckets = %#v, want lt_10k=1", snapshot.MCPHTTP.ResponseBytes)
	}

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-user-agent", "query-value"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("snapshot leaks %q: %s", secret, encoded)
		}
	}
}
