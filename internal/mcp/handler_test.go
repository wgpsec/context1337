package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wgpsec/context1337/internal/buildinfo"
	"github.com/wgpsec/context1337/internal/usage"
)

func TestNewMCPServer_Instructions_LiteMode(t *testing.T) {
	db := setupUnifiedTest(t).DB
	dir := t.TempDir()

	_ = NewMCPServer(db, dir, ToolModeLite, 0)
	_ = NewMCPServer(db, dir, ToolModeFull, 0)
}

func TestNewMCPServerRecordsSearchQueriesAndZeroResults(t *testing.T) {
	db := setupUnifiedTest(t).DB
	collector := usage.NewCollector()
	handler := NewMCPServer(db, t.TempDir(), ToolModeLite, 0, collector)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := gomcp.NewClient(&gomcp.Implementation{Name: "usage-test", Version: "0.1"}, nil)
	session, err := client.Connect(ctx, &gomcp.StreamableClientTransport{Endpoint: server.URL}, nil)
	if err != nil {
		t.Fatalf("connect MCP client: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	const sensitiveQuery = "unique-sensitive-query-7f92"
	result, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name:      "search_security",
		Arguments: map[string]any{"query": sensitiveQuery},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool returned MCP error: %#v", result.Content)
	}
	matchedResult, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name:      "search_security",
		Arguments: map[string]any{"query": "SQL  Injection", "type": "skill"},
	})
	if err != nil {
		t.Fatalf("call matched search tool: %v", err)
	}
	if matchedResult.IsError {
		t.Fatalf("matched search returned MCP error: %#v", matchedResult.Content)
	}
	errorResult, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name:      "get_security_detail",
		Arguments: map[string]any{"id": "absec://builtin/skill/missing-sensitive-resource"},
	})
	if err != nil {
		t.Fatalf("call missing detail tool: %v", err)
	}
	if !errorResult.IsError {
		t.Fatalf("missing detail result IsError = false, want true")
	}

	snapshot := collector.Snapshot()
	if snapshot.Tools.CallsTotal != 3 || snapshot.Tools.CallsByName["search_security"] != 2 || snapshot.Tools.CallsByName["get_security_detail"] != 1 {
		t.Errorf("tool metrics = %#v, want two searches and one detail call", snapshot.Tools)
	}
	if snapshot.Tools.CallsByStatus["success"] != 2 || snapshot.Tools.CallsByStatus["error"] != 1 {
		t.Errorf("tool statuses = %#v, want two successes and one error", snapshot.Tools.CallsByStatus)
	}
	if snapshot.Search.QueriesTotal != 2 || snapshot.Search.MatchedTotal != 1 || snapshot.Search.ZeroResultTotal != 1 {
		t.Errorf("search metrics = %#v, want two queries with one match and one zero result", snapshot.Search)
	}
	if len(snapshot.Search.ZeroResultQueries) != 1 || snapshot.Search.ZeroResultQueries[0].Query != sensitiveQuery {
		t.Errorf("zero-result queries = %#v, want %q", snapshot.Search.ZeroResultQueries, sensitiveQuery)
	}
	if snapshot.MCPHTTP.RequestsTotal < 2 {
		t.Errorf("HTTP requests = %d, want at least initialize + tool call", snapshot.MCPHTTP.RequestsTotal)
	}
	if snapshot.MCP.ActiveSessions != 1 {
		t.Errorf("active sessions = %d, want 1", snapshot.MCP.ActiveSessions)
	}
}

func TestNewMCPServer_HeaderDispatch(t *testing.T) {
	db := setupUnifiedTest(t).DB
	dir := t.TempDir()
	h := NewMCPServer(db, dir, ToolModeLite, 0)

	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}`

	for _, tc := range []struct {
		name            string
		header          string
		wantInstruction string
	}{
		{"lite (no header)", "", "search_security"},
		{"full (X-Tool-Mode: full)", "full", "search_* or list_*"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(initBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			if tc.header != "" {
				req.Header.Set("X-Tool-Mode", tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code >= 500 {
				t.Fatalf("mode=%q: got status %d, want < 500", tc.name, rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, tc.wantInstruction) {
				t.Errorf("mode=%q: response does not contain %q; body snippet: %.200s",
					tc.name, tc.wantInstruction, body)
			}
		})
	}
}

func TestNewMCPServer_InitializeReportsReleaseVersion(t *testing.T) {
	db := setupUnifiedTest(t).DB
	h := NewMCPServer(db, t.TempDir(), ToolModeLite, 0)
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(initBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("initialize status = %d", rec.Code)
	}
	// Assert the reported version is buildinfo's, not a pinned literal: this
	// assertion rotted for two releases because nothing in CI runs go test.
	if want := `"version":"` + buildinfo.Version + `"`; !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("initialize response does not report %s: %s", want, rec.Body.String())
	}
}

const (
	testMCPInitialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"timeout-test","version":"0.1"}}}`
	testMCPToolsList  = `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
)

func postMCPTest(t *testing.T, h http.Handler, sessionID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func deleteMCPTest(t *testing.T, h http.Handler, sessionID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	req.Header.Set("Mcp-Session-Id", sessionID)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func initializeMCPTest(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := postMCPTest(t, h, "", testMCPInitialize)
	if rec.Code != http.StatusOK {
		t.Fatalf("initialize status = %d, body: %s", rec.Code, rec.Body.String())
	}
	sessionID := rec.Header().Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Fatal("initialize response omitted Mcp-Session-Id")
	}
	ack := postMCPTest(t, h, sessionID, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if ack.Code != http.StatusAccepted && ack.Code != http.StatusOK {
		t.Fatalf("initialized notification status = %d, body: %s", ack.Code, ack.Body.String())
	}
	return sessionID
}

func waitActiveSessions(t *testing.T, collector *usage.Collector, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := collector.Snapshot().MCP.ActiveSessions; got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("active sessions = %d, want %d", collector.Snapshot().MCP.ActiveSessions, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNewMCPServer_SessionIdleTimeout(t *testing.T) {
	db := setupUnifiedTest(t).DB
	collector := usage.NewCollector()
	h := NewMCPServer(db, t.TempDir(), ToolModeLite, 150*time.Millisecond, collector)

	sessionID := initializeMCPTest(t, h)
	waitActiveSessions(t, collector, 1)
	time.Sleep(350 * time.Millisecond)

	rec := postMCPTest(t, h, sessionID, testMCPToolsList)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("tools/list after timeout status = %d, want 404 (body: %s)", rec.Code, rec.Body.String())
	}
	waitActiveSessions(t, collector, 0)
}

func TestNewMCPServer_SessionTimeoutResetsOnPost(t *testing.T) {
	db := setupUnifiedTest(t).DB
	collector := usage.NewCollector()
	h := NewMCPServer(db, t.TempDir(), ToolModeLite, 250*time.Millisecond, collector)

	sessionID := initializeMCPTest(t, h)
	time.Sleep(100 * time.Millisecond)
	if rec := postMCPTest(t, h, sessionID, testMCPToolsList); rec.Code != http.StatusOK {
		t.Fatalf("first post status = %d, body: %s", rec.Code, rec.Body.String())
	}
	time.Sleep(100 * time.Millisecond)
	if rec := postMCPTest(t, h, sessionID, testMCPToolsList); rec.Code != http.StatusOK {
		t.Fatalf("second post status = %d, body: %s", rec.Code, rec.Body.String())
	}
	time.Sleep(450 * time.Millisecond)
	if rec := postMCPTest(t, h, sessionID, testMCPToolsList); rec.Code != http.StatusNotFound {
		t.Fatalf("post after idle status = %d, want 404 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestNewMCPServer_SessionDeleteClosesSession(t *testing.T) {
	db := setupUnifiedTest(t).DB
	collector := usage.NewCollector()
	h := NewMCPServer(db, t.TempDir(), ToolModeLite, time.Hour, collector)

	sessionID := initializeMCPTest(t, h)
	rec := deleteMCPTest(t, h, sessionID)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204", rec.Code)
	}
	if rec := postMCPTest(t, h, sessionID, testMCPToolsList); rec.Code != http.StatusNotFound {
		t.Fatalf("tools/list after DELETE status = %d, want 404", rec.Code)
	}
	waitActiveSessions(t, collector, 0)
}

func TestNewMCPServer_SessionTimeoutDisabled(t *testing.T) {
	db := setupUnifiedTest(t).DB
	collector := usage.NewCollector()
	h := NewMCPServer(db, t.TempDir(), ToolModeLite, 0, collector)

	sessionID := initializeMCPTest(t, h)
	time.Sleep(250 * time.Millisecond)
	if rec := postMCPTest(t, h, sessionID, testMCPToolsList); rec.Code != http.StatusOK {
		t.Fatalf("disabled timeout closed the session: status = %d, body: %s", rec.Code, rec.Body.String())
	}
	waitActiveSessions(t, collector, 1)
}
