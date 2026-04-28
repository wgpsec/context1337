package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewMCPServer_Instructions_LiteMode(t *testing.T) {
	db := setupUnifiedTest(t).DB
	dir := t.TempDir()

	_ = NewMCPServer(db, dir, ToolModeLite)
	_ = NewMCPServer(db, dir, ToolModeFull)
}

func TestNewMCPServer_HeaderDispatch(t *testing.T) {
	db := setupUnifiedTest(t).DB
	dir := t.TempDir()
	h := NewMCPServer(db, dir, ToolModeLite)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}`

	for _, tc := range []struct {
		name   string
		header string
	}{
		{"lite (no header)", ""},
		{"full (X-Tool-Mode: full)", "full"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			if tc.header != "" {
				req.Header.Set("X-Tool-Mode", tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code >= 500 {
				t.Errorf("mode=%q: got status %d, want < 500", tc.name, rec.Code)
			}
		})
	}
}
