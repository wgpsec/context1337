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
		Name:        "list_skills",
		Description: "List penetration testing skills by category. Params: category (optional: exploit|recon|tool|cloud|ctf|lateral|evasion|malware|dfir|threat-intel|ai-security|code-audit|postexploit|general), difficulty (optional: easy|medium|hard), offset (optional, default 0), limit (optional, default 50)",
	}, wrapHandler(svc.ListSkills))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "search_skill",
		Description: "Search penetration testing skills by keyword. Params: query (keyword), category (optional: exploit|recon|tool|cloud|ctf|lateral), difficulty (optional: easy|medium|hard), limit (optional, default 10)",
	}, wrapHandler(svc.SearchSkill))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_skill",
		Description: "Get skill detail by exact name. Params: name (skill name from search/list results), depth (optional: metadata|summary|full, default summary)",
	}, wrapHandler(svc.GetSkill))

	// --- Dictionary tools ---
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "search_dicts",
		Description: "Search security dictionaries by keyword. Params: query (keyword e.g. password, SSH, admin), type (optional: auth|network|port|web|regular), limit (optional, default 20)",
	}, wrapHandler(svc.SearchDicts))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "list_dicts",
		Description: "List all security dictionaries. Params: type (optional: auth|network|port|web|regular)",
	}, wrapHandler(svc.ListDicts))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_dict",
		Description: "Read dictionary file content with pagination. Params: path (relative path from list_dicts e.g. Auth/password/Top100.txt), limit (optional, default 200 lines), offset (optional, default 0). Response includes total_lines for pagination.",
	}, wrapHandler(svc.GetDict))

	// --- Payload tools ---
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "search_payload",
		Description: "Search security payloads. Params: query (keyword), type (optional: sqli|xss|ssrf|xxe|lfi|rce|cors)",
	}, wrapHandler(svc.SearchPayload))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_payload",
		Description: "Read payload file content with pagination. Params: path (relative path from search_payload e.g. XSS/events.txt), limit (optional, default 200 lines), offset (optional, default 0). Response includes total_lines for pagination.",
	}, wrapHandler(svc.GetPayload))

	// --- Tool config tools ---
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "search_tools",
		Description: "Search security tools by keyword. Params: query (keyword e.g. nmap, port scan, dns), function (optional: scan|fuzz|osint|poc|brute|postexploit), limit (optional, default 10)",
	}, wrapHandler(svc.SearchTools))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "list_tools",
		Description: "List security tool configurations. Params: function (optional: scan|fuzz|osint|poc|brute|postexploit)",
	}, wrapHandler(svc.ListTools))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_tool",
		Description: "Get full YAML configuration for a tool. Params: name (tool name from list_tools/search_tools e.g. nmap, sqlmap, dnsx)",
	}, wrapHandler(svc.GetTool))

	return gomcp.NewStreamableHTTPHandler(func(_ *http.Request) *gomcp.Server {
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
