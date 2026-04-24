package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/wgpsec/context1337/internal/mcp/benchlog"
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
	// ToolModeFull registers the 12 per-type tools (search/list/get per resource type).
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

	instructions := `Penetration testing and offensive security knowledge base.
Use when: exploit techniques, post-exploitation tactics, cloud security assessment, password/bruteforce wordlists, attack payloads, vulnerability PoCs.
Do not use for: general programming, defensive security configuration, compliance/audit checklists, or non-security topics.
Resources: skills (attack methodologies), dicts (wordlists), payloads (attack payloads), vulns (CVE-specific PoCs).`

	switch mode {
	case ToolModeFull:
		instructions += "\nWorkflow: use search_* or list_* to find resources, then get_* for details."
	default:
		instructions += "\nWorkflow: search_security to find resources → get_security_detail for skills/vulns → read_security_file for dicts/payloads."
	}

	server := gomcp.NewServer(&gomcp.Implementation{
		Name:    "aboutsecurity",
		Version: "0.5.0",
	}, &gomcp.ServerOptions{Instructions: instructions})

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
		Description: "Search the AboutSecurity penetration testing knowledge base. Covers: exploit techniques (SQL injection, XSS, SSRF, RCE...), password/bruteforce wordlists, and attack payloads. To search vulnerabilities, you MUST specify type=\"vuln\" explicitly — vulnerabilities are excluded from default search to avoid polluting technique-oriented results. Vuln search supports additional filters: severity (CRITICAL/HIGH/MEDIUM/LOW) and product. Params: query (optional keyword — omit to list all), type (optional: skill|dict|payload|vuln — omit to search all non-vuln types), category (optional), difficulty (optional, skill only), severity (optional, vuln only), product (optional, vuln only), offset (default 0), limit (default 10, vuln default 50). Returns the top results ranked by relevance — increase limit only when you need broader coverage.",
		Annotations: &gomcp.ToolAnnotations{ReadOnlyHint: true},
	}, wrapHandler(svc.Search))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_security_detail",
		Description: "Get detailed penetration testing knowledge for a skill or vulnerability by name. ALWAYS use this tool instead of reading files directly — it handles pagination automatically. Params: name (from search results), type (skill|vuln), depth (optional — skill: metadata|summary|full, default summary; vuln: brief|full, default brief). For skills with many references, depth=full returns paginated references: use ref_offset (default 0) and ref_limit (default 3) to page through them. The response includes ref_total showing the total number of references available. Start with depth=summary to get the skill body, then use depth=full with ref_offset/ref_limit to fetch specific references as needed. Returns full content including body (skill), or vulnerability details with severity/product/PoC (vuln).",
		Annotations: &gomcp.ToolAnnotations{ReadOnlyHint: true},
	}, wrapHandler(svc.Get))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "read_security_file",
		Description: "Read security dictionary (wordlists/passwords) or attack payload file content with line-level pagination. Use after search_security to read file data. Params: path (from search results, e.g. Auth/password/Top100.txt), type (dict|payload), offset (default 0 lines), limit (default 200 lines). Returns file content with total_lines count.",
		Annotations: &gomcp.ToolAnnotations{ReadOnlyHint: true},
	}, wrapHandler(svc.GetFile))
}

// maxResponseBytes is the safety limit for MCP tool responses.
// Responses exceeding this size would overflow LLM context windows.
const maxResponseBytes = 150_000

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

		if len(data) > maxResponseBytes {
			return nil, nil, fmt.Errorf(
				"response too large (%dKB > %dKB limit); retry with depth=summary to get the body without references, then use depth=full with ref_offset/ref_limit to page through references one at a time",
				len(data)/1024, maxResponseBytes/1024,
			)
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
