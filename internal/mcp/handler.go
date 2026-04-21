package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Esonhugh/context1337/internal/mcp/benchlog"
	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// BenchLogger is an optional benchmark logger. When non-nil every tool call
// is recorded (tool name, input, response size, item count, latency).
var BenchLogger *benchlog.Logger

// ToolMode controls which set of tools the MCP server exposes.
type ToolMode string

const (
	// ToolModeLite registers the 3 core tools (search, detail, file).
	ToolModeLite ToolMode = "lite"
	// ToolModeFull registers all tools (12 planned). Currently falls back to lite.
	ToolModeFull ToolMode = "full"
)

// NewService creates a new MCP service with all handlers.
func NewService(db *sql.DB, dataDir string) *Service {
	return &Service{DB: db, DataDir: dataDir}
}

// NewMCPServer creates an MCP server and returns an HTTP handler.
// The mode parameter controls which tools are registered.
func NewMCPServer(db *sql.DB, dataDir string, mode ToolMode) http.Handler {
	svc := NewService(db, dataDir)
	server := gomcp.NewServer(&gomcp.Implementation{
		Name:    "aboutsecurity",
		Version: "0.5.0",
	}, nil)

	switch mode {
	case ToolModeFull:
		registerFullTools(server, svc)
	default:
		registerLiteTools(server, svc)
	}

	return gomcp.NewStreamableHTTPHandler(func(_ *http.Request) *gomcp.Server {
		return server
	}, nil)
}

// registerLiteTools registers the 3 core tools: search, detail, and file read.
func registerLiteTools(server *gomcp.Server, svc *Service) {
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "search_security",
		Description: "Search the AboutSecurity penetration testing knowledge base. Covers: exploit techniques (SQL injection, XSS, SSRF, RCE...), password/bruteforce wordlists, attack payloads, and security tool configs (nmap, sqlmap, dirsearch...). ALWAYS use this tool when the user asks about hacking, penetration testing, security vulnerabilities, dictionaries, payloads, or security tools. Params: query (optional keyword — omit to list all), type (optional: skill|dict|payload|tool — omit to search all types), category (optional), difficulty (optional, skill only: easy|medium|hard), offset (default 0), limit (default 20). Returns paginated results with type, name, description, category.",
	}, wrapHandler(svc.Search))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_security_detail",
		Description: "Get detailed penetration testing knowledge for a skill or tool by name. Use after search_security to retrieve full content. Params: name (from search results), type (skill|tool), depth (optional, skill only: metadata|summary|full, default summary). depth=full includes references. Returns full content including body (skill) or config YAML (tool).",
	}, wrapHandler(svc.Get))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "read_security_file",
		Description: "Read security dictionary (wordlists/passwords) or attack payload file content with line-level pagination. Use after search_security to read file data. Params: path (from search results, e.g. Auth/password/Top100.txt), type (dict|payload), offset (default 0 lines), limit (default 200 lines). Returns file content with total_lines count.",
	}, wrapHandler(svc.GetFile))
}

// wrapHandler adapts a typed service method (func(ctx, In) (Out, error)) into
// the MCP SDK's ToolHandlerFor signature. The Out is serialised as JSON text
// content.
func wrapHandler[In any, Out any](fn func(context.Context, In) (Out, error)) gomcp.ToolHandlerFor[In, any] {
	return func(ctx context.Context, req *gomcp.CallToolRequest, input In) (*gomcp.CallToolResult, any, error) {
		start := time.Now()

		out, err := fn(ctx, input)
		if err != nil {
			return nil, nil, err
		}
		data, err := json.Marshal(out)
		if err != nil {
			return nil, nil, err
		}

		if BenchLogger != nil {
			inputJSON, _ := json.Marshal(input)
			items := countItems(data)
			BenchLogger.Log(benchlog.Entry{
				Tool:          req.Params.Name,
				Input:         inputJSON,
				ResponseBytes: len(data),
				ResponseItems: items,
				DurationMs:    time.Since(start).Milliseconds(),
			})
		}

		return &gomcp.CallToolResult{
			Content: []gomcp.Content{
				&gomcp.TextContent{Text: string(data)},
			},
		}, nil, nil
	}
}

// countItems inspects JSON-encoded data for an "items" array and returns its
// length. If the data is not an object or has no "items" key it returns 1
// (single-resource get responses).
func countItems(data []byte) int {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return 1
	}
	raw, ok := obj["items"]
	if !ok {
		return 1
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return 1
	}
	return len(arr)
}
