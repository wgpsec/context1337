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

// NewMCPServer creates an MCP protocol server with all 12 tools registered
// and returns an http.Handler that serves it via Streamable HTTP transport.
func NewMCPServer(db *sql.DB, dataDir string) http.Handler {
	svc := NewService(db, dataDir)
	server := gomcp.NewServer(&gomcp.Implementation{
		Name:    "aboutsecurity",
		Version: "0.2.0",
	}, nil)

	// --- Skill tools ---
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "list_skills",
		Description: "List penetration testing skills. Params: category (optional: exploit|recon|tool|cloud|ctf|lateral|evasion|malware|dfir|threat-intel|ai-security|code-audit|postexploit|general), difficulty (optional: easy|medium|hard), offset (default 0), limit (default 50). Returns paginated result with total count.",
	}, wrapHandler(svc.ListSkills))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "search_skill",
		Description: "Search penetration testing skills by keyword. Params: query (keyword), category (optional), difficulty (optional), offset (default 0), limit (default 10). Returns paginated result with total count.",
	}, wrapHandler(svc.SearchSkill))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_skill",
		Description: "Get skill detail by exact name. Params: name (skill name from search/list results), depth (optional: metadata|summary|full, default summary)",
	}, wrapHandler(svc.GetSkill))

	// --- Dictionary tools ---
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "search_dicts",
		Description: "Search security dictionaries by keyword. Params: query (keyword), category (optional: auth|network|port|web|regular), offset (default 0), limit (default 20). Returns paginated result with total count.",
	}, wrapHandler(svc.SearchDicts))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "list_dicts",
		Description: "List security dictionaries. Params: category (optional: auth|network|port|web|regular), offset (default 0), limit (default 50). Returns paginated result with total count.",
	}, wrapHandler(svc.ListDicts))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_dict",
		Description: "Read dictionary file content with pagination. Params: path (relative path from list/search e.g. Auth/password/Top100.txt), limit (default 200 lines), offset (default 0). Response includes total_lines.",
	}, wrapHandler(svc.GetDict))

	// --- Payload tools ---
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "search_payload",
		Description: "Search security payloads by keyword. Params: query (keyword), category (optional: sqli|xss|ssrf|xxe|lfi|rce|cors), offset (default 0), limit (default 20). Returns paginated result with total count.",
	}, wrapHandler(svc.SearchPayload))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "list_payloads",
		Description: "List security payloads. Params: category (optional: sqli|xss|ssrf|xxe|lfi|rce|cors), offset (default 0), limit (default 50). Returns paginated result with total count.",
	}, wrapHandler(svc.ListPayloads))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_payload",
		Description: "Read payload file content with pagination. Params: path (relative path from list/search e.g. XSS/events.txt), limit (default 200 lines), offset (default 0). Response includes total_lines.",
	}, wrapHandler(svc.GetPayload))

	// --- Tool config tools ---
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "search_tools",
		Description: "Search security tools by keyword. Params: query (keyword), category (optional: scan|fuzz|osint|poc|brute|postexploit), offset (default 0), limit (default 10). Returns paginated result with total count.",
	}, wrapHandler(svc.SearchTools))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "list_tools",
		Description: "List security tool configurations. Params: category (optional: scan|fuzz|osint|poc|brute|postexploit), offset (default 0), limit (default 50). Returns paginated result with total count.",
	}, wrapHandler(svc.ListTools))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_tool",
		Description: "Get full YAML configuration for a tool. Params: name (tool name from list/search e.g. nmap, sqlmap, dnsx). Returns config YAML plus metadata (category, binary, homepage).",
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
