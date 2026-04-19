package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// NewService creates a new MCP service with all handlers.
func NewService(db *sql.DB, dataDir string) *Service {
	return &Service{DB: db, DataDir: dataDir}
}

// NewMCPServer creates an MCP protocol server with all 8 tools registered
// and returns an http.Handler that serves it via SSE transport.
func NewMCPServer(db *sql.DB, dataDir string) http.Handler {
	svc := NewService(db, dataDir)
	server := gomcp.NewServer(&gomcp.Implementation{
		Name:    "aboutsecurity",
		Version: "0.1.0",
	}, nil)

	// --- Skill tools ---
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "search_skill",
		Description: "Search penetration testing skills by keyword, category, or difficulty",
	}, wrapHandler(svc.SearchSkill))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_skill",
		Description: "Get detailed information about a specific skill by name",
	}, wrapHandler(svc.GetSkill))

	// --- Dictionary tools ---
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "list_dicts",
		Description: "List available security dictionaries, optionally filtered by type",
	}, wrapHandler(svc.ListDicts))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_dict",
		Description: "Get the content of a specific dictionary file with pagination",
	}, wrapHandler(svc.GetDict))

	// --- Payload tools ---
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "search_payload",
		Description: "Search security payloads by keyword or type (sqli, xss, ssrf, etc.)",
	}, wrapHandler(svc.SearchPayload))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_payload",
		Description: "Get the content of a specific payload file with pagination",
	}, wrapHandler(svc.GetPayload))

	// --- Tool config tools ---
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "list_tools",
		Description: "List available security tool configurations by function category",
	}, wrapHandler(svc.ListTools))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_tool",
		Description: "Get the full configuration for a specific security tool",
	}, wrapHandler(svc.GetTool))

	return gomcp.NewSSEHandler(func(_ *http.Request) *gomcp.Server {
		return server
	}, nil)
}

// wrapHandler adapts a typed service method (func(ctx, In) (Out, error)) into
// the MCP SDK's ToolHandlerFor signature. The Out is serialised as JSON text
// content.
func wrapHandler[In any, Out any](fn func(context.Context, In) (Out, error)) gomcp.ToolHandlerFor[In, any] {
	return func(ctx context.Context, req *gomcp.CallToolRequest, input In) (*gomcp.CallToolResult, any, error) {
		out, err := fn(ctx, input)
		if err != nil {
			return nil, nil, err
		}
		data, err := json.Marshal(out)
		if err != nil {
			return nil, nil, err
		}
		return &gomcp.CallToolResult{
			Content: []gomcp.Content{
				&gomcp.TextContent{Text: string(data)},
			},
		}, nil, nil
	}
}
