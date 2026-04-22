package mcp

import (
	"context"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- Search adapter inputs (no Type field — injected by adapter) ---

type SearchSkillInput struct {
	Query      string `json:"query,omitempty"      jsonschema:"Search keywords for skill lookup"`
	Category   string `json:"category,omitempty"   jsonschema:"Filter by category"`
	Difficulty string `json:"difficulty,omitempty" jsonschema:"Filter by difficulty: easy|medium|hard"`
	Offset     int    `json:"offset,omitempty"     jsonschema:"Pagination offset (default 0)"`
	Limit      int    `json:"limit,omitempty"      jsonschema:"Max results (default 20)"`
}

type SearchDictsInput struct {
	Query    string `json:"query,omitempty"    jsonschema:"Search keywords for dictionary lookup"`
	Category string `json:"category,omitempty" jsonschema:"Filter by category"`
	Offset   int    `json:"offset,omitempty"   jsonschema:"Pagination offset (default 0)"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results (default 20)"`
}

type SearchPayloadInput struct {
	Query    string `json:"query,omitempty"    jsonschema:"Search keywords for payload lookup"`
	Category string `json:"category,omitempty" jsonschema:"Filter by category"`
	Offset   int    `json:"offset,omitempty"   jsonschema:"Pagination offset (default 0)"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results (default 20)"`
}

type SearchToolsInput struct {
	Query    string `json:"query,omitempty"    jsonschema:"Search keywords for tool lookup"`
	Category string `json:"category,omitempty" jsonschema:"Filter by category"`
	Offset   int    `json:"offset,omitempty"   jsonschema:"Pagination offset (default 0)"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results (default 20)"`
}

type SearchVulnInput struct {
	Query    string `json:"query,omitempty"    jsonschema:"Search keywords for vulnerability lookup"`
	Category string `json:"category,omitempty" jsonschema:"Filter by category: ai|cloud|middleware|network|web"`
	Severity string `json:"severity,omitempty" jsonschema:"Filter by severity: CRITICAL|HIGH|MEDIUM|LOW"`
	Product  string `json:"product,omitempty"  jsonschema:"Filter by product name"`
	Offset   int    `json:"offset,omitempty"   jsonschema:"Pagination offset (default 0)"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results (default 50)"`
}

// --- List adapter inputs (no Type or Query field) ---

type ListSkillsInput struct {
	Category   string `json:"category,omitempty"   jsonschema:"Filter by category"`
	Difficulty string `json:"difficulty,omitempty" jsonschema:"Filter by difficulty: easy|medium|hard"`
	Offset     int    `json:"offset,omitempty"     jsonschema:"Pagination offset (default 0)"`
	Limit      int    `json:"limit,omitempty"      jsonschema:"Max results (default 20)"`
}

type ListDictsInput struct {
	Category string `json:"category,omitempty" jsonschema:"Filter by category"`
	Offset   int    `json:"offset,omitempty"   jsonschema:"Pagination offset (default 0)"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results (default 20)"`
}

type ListPayloadsInput struct {
	Category string `json:"category,omitempty" jsonschema:"Filter by category"`
	Offset   int    `json:"offset,omitempty"   jsonschema:"Pagination offset (default 0)"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results (default 20)"`
}

type ListToolsInput struct {
	Category string `json:"category,omitempty" jsonschema:"Filter by category"`
	Offset   int    `json:"offset,omitempty"   jsonschema:"Pagination offset (default 0)"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results (default 20)"`
}

type ListVulnsInput struct {
	Category string `json:"category,omitempty" jsonschema:"Filter by category: ai|cloud|middleware|network|web"`
	Severity string `json:"severity,omitempty" jsonschema:"Filter by severity: CRITICAL|HIGH|MEDIUM|LOW"`
	Product  string `json:"product,omitempty"  jsonschema:"Filter by product name"`
	Offset   int    `json:"offset,omitempty"   jsonschema:"Pagination offset (default 0)"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results (default 50)"`
}

// --- Get adapter inputs ---

type GetSkillInput struct {
	Name  string `json:"name"            jsonschema:"Skill name (from search results)"`
	Depth string `json:"depth,omitempty" jsonschema:"Loading depth: metadata|summary|full (default summary). full includes references."`
}

type GetToolInput struct {
	Name string `json:"name" jsonschema:"Tool name (from search results)"`
}

type GetDictInput struct {
	Path   string `json:"path"             jsonschema:"Relative file path from search results (e.g. Auth/password/Top100.txt)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Line offset for pagination (default 0)"`
	Limit  int    `json:"limit,omitempty"  jsonschema:"Max lines to return (default 200)"`
}

type GetPayloadInput struct {
	Path   string `json:"path"             jsonschema:"Relative file path from search results (e.g. XSS/xss-payload-list.txt)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Line offset for pagination (default 0)"`
	Limit  int    `json:"limit,omitempty"  jsonschema:"Max lines to return (default 200)"`
}

type GetVulnInput struct {
	Name  string `json:"name"            jsonschema:"Vulnerability ID (CVE/CNVD from search results)"`
	Depth string `json:"depth,omitempty" jsonschema:"Loading depth: brief|full (default brief). full includes PoC and remediation."`
}

// --- Search adapters ---

func (s *Service) searchSkillAdapter(ctx context.Context, in SearchSkillInput) (*SearchResult, error) {
	return s.Search(ctx, SearchInput{
		Query: in.Query, Type: "skill", Category: in.Category,
		Difficulty: in.Difficulty, Offset: in.Offset, Limit: in.Limit,
	})
}

func (s *Service) searchDictsAdapter(ctx context.Context, in SearchDictsInput) (*SearchResult, error) {
	return s.Search(ctx, SearchInput{
		Query: in.Query, Type: "dict", Category: in.Category,
		Offset: in.Offset, Limit: in.Limit,
	})
}

func (s *Service) searchPayloadAdapter(ctx context.Context, in SearchPayloadInput) (*SearchResult, error) {
	return s.Search(ctx, SearchInput{
		Query: in.Query, Type: "payload", Category: in.Category,
		Offset: in.Offset, Limit: in.Limit,
	})
}

func (s *Service) searchToolsAdapter(ctx context.Context, in SearchToolsInput) (*SearchResult, error) {
	return s.Search(ctx, SearchInput{
		Query: in.Query, Type: "tool", Category: in.Category,
		Offset: in.Offset, Limit: in.Limit,
	})
}

func (s *Service) searchVulnAdapter(ctx context.Context, in SearchVulnInput) (*SearchResult, error) {
	return s.Search(ctx, SearchInput{
		Query: in.Query, Type: "vuln", Category: in.Category,
		Severity: in.Severity, Product: in.Product,
		Offset: in.Offset, Limit: in.Limit,
	})
}

// --- List adapters ---

func (s *Service) listSkillsAdapter(ctx context.Context, in ListSkillsInput) (*SearchResult, error) {
	return s.Search(ctx, SearchInput{
		Type: "skill", Category: in.Category,
		Difficulty: in.Difficulty, Offset: in.Offset, Limit: in.Limit,
	})
}

func (s *Service) listDictsAdapter(ctx context.Context, in ListDictsInput) (*SearchResult, error) {
	return s.Search(ctx, SearchInput{
		Type: "dict", Category: in.Category,
		Offset: in.Offset, Limit: in.Limit,
	})
}

func (s *Service) listPayloadsAdapter(ctx context.Context, in ListPayloadsInput) (*SearchResult, error) {
	return s.Search(ctx, SearchInput{
		Type: "payload", Category: in.Category,
		Offset: in.Offset, Limit: in.Limit,
	})
}

func (s *Service) listToolsAdapter(ctx context.Context, in ListToolsInput) (*SearchResult, error) {
	return s.Search(ctx, SearchInput{
		Type: "tool", Category: in.Category,
		Offset: in.Offset, Limit: in.Limit,
	})
}

func (s *Service) listVulnsAdapter(ctx context.Context, in ListVulnsInput) (*SearchResult, error) {
	return s.Search(ctx, SearchInput{
		Type: "vuln", Category: in.Category,
		Severity: in.Severity, Product: in.Product,
		Offset: in.Offset, Limit: in.Limit,
	})
}

// --- Get adapters ---

func (s *Service) getSkillAdapter(ctx context.Context, in GetSkillInput) (*GetResult, error) {
	return s.Get(ctx, GetInput{Name: in.Name, Type: "skill", Depth: in.Depth})
}

func (s *Service) getToolAdapter(ctx context.Context, in GetToolInput) (*GetResult, error) {
	return s.Get(ctx, GetInput{Name: in.Name, Type: "tool"})
}

func (s *Service) getDictAdapter(ctx context.Context, in GetDictInput) (*GetFileResult, error) {
	return s.GetFile(ctx, GetFileInput{Path: in.Path, Type: "dict", Offset: in.Offset, Limit: in.Limit})
}

func (s *Service) getPayloadAdapter(ctx context.Context, in GetPayloadInput) (*GetFileResult, error) {
	return s.GetFile(ctx, GetFileInput{Path: in.Path, Type: "payload", Offset: in.Offset, Limit: in.Limit})
}

func (s *Service) getVulnAdapter(ctx context.Context, in GetVulnInput) (*GetResult, error) {
	return s.Get(ctx, GetInput{Name: in.Name, Type: "vuln", Depth: in.Depth})
}

// --- Registration ---

// registerFullTools registers all 15 per-type tools with security-keyword-enriched descriptions.
func registerFullTools(server *gomcp.Server, svc *Service) {
	// Search tools
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "search_skill",
		Description: "Search penetration testing skills and exploit techniques (SQL injection, XSS, SSRF, RCE, privilege escalation, buffer overflow, command injection, path traversal, authentication bypass, CSRF). Use when the user asks about hacking techniques or vulnerability exploitation. Returns paginated results with name, description, category, and difficulty.",
	}, wrapHandler(svc.searchSkillAdapter))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "search_dicts",
		Description: "Search password wordlists and bruteforce dictionaries for penetration testing (rockyou, common passwords, credential lists, username lists, directory bruteforce, subdomain enumeration). Use when the user needs dictionaries for password cracking or fuzzing. Returns paginated results.",
	}, wrapHandler(svc.searchDictsAdapter))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "search_payload",
		Description: "Search attack payloads and exploit strings for penetration testing (XSS payloads, SQL injection strings, SSRF URLs, XXE payloads, command injection, template injection, LDAP injection, CRLF injection). Use when the user needs ready-made attack payloads. Returns paginated results.",
	}, wrapHandler(svc.searchPayloadAdapter))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "search_tools",
		Description: "Search security tool configurations and references (nmap, sqlmap, dirsearch, burp suite, metasploit, nuclei, ffuf, gobuster, hydra, john). Use when the user asks about security tools, their options, or usage. Returns paginated results with tool metadata.",
	}, wrapHandler(svc.searchToolsAdapter))

	// List tools
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "list_skills",
		Description: "List all available penetration testing skills and exploit techniques. Browse by category or difficulty without a search query. Supports pagination with offset and limit. Use to discover available hacking skills, vulnerability classes, and attack methods.",
	}, wrapHandler(svc.listSkillsAdapter))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "list_dicts",
		Description: "List all available password wordlists and bruteforce dictionaries. Browse dictionary categories without a search query. Supports pagination. Use to discover available wordlists for password cracking, fuzzing, and enumeration.",
	}, wrapHandler(svc.listDictsAdapter))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "list_payloads",
		Description: "List all available attack payloads and exploit strings. Browse payload categories without a search query. Supports pagination. Use to discover available payloads for XSS, SQL injection, SSRF, and other attack vectors.",
	}, wrapHandler(svc.listPayloadsAdapter))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "list_tools",
		Description: "List all available security tool configurations and references. Browse tool categories without a search query. Supports pagination. Use to discover available security tools like nmap, sqlmap, burp suite, and metasploit.",
	}, wrapHandler(svc.listToolsAdapter))

	// Get tools
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_skill",
		Description: "Get detailed penetration testing skill content by name. Returns full exploit technique documentation including description, body, and optional references. Use after search_skill or list_skills to retrieve complete skill details. Set depth=full to include reference files.",
	}, wrapHandler(svc.getSkillAdapter))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_tool",
		Description: "Get detailed security tool configuration and documentation by name. Returns tool description, binary name, homepage, and full YAML config. Use after search_tools or list_tools to retrieve complete tool details including usage examples.",
	}, wrapHandler(svc.getToolAdapter))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_dict",
		Description: "Read password dictionary or wordlist file content with line-level pagination. Returns file lines with total line count. Use after search_dicts or list_dicts to read actual dictionary content. Supports offset and limit for large files.",
	}, wrapHandler(svc.getDictAdapter))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_payload",
		Description: "Read attack payload file content with line-level pagination. Returns payload strings with total line count. Use after search_payload or list_payloads to read actual payload content. Supports offset and limit for large files.",
	}, wrapHandler(svc.getPayloadAdapter))

	// Vuln tools
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "search_vuln",
		Description: "Search vulnerability database by keyword. Supports severity (CRITICAL/HIGH/MEDIUM/LOW) and product filters. Use this for specific CVE/CNVD lookups or product-targeted vulnerability discovery. Returns paginated results with severity, product, vendor, and category.",
	}, wrapHandler(svc.searchVulnAdapter))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "list_vulns",
		Description: "List vulnerabilities with pagination (default 50). Supports category (ai/cloud/middleware/network/web), severity, and product filters. Returns summary only — use get_vuln for full details and PoC.",
	}, wrapHandler(svc.listVulnsAdapter))

	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "get_vuln",
		Description: "Get vulnerability detail by name (CVE/CNVD ID). depth=\"brief\" (default) returns structured fields and description. depth=\"full\" returns complete content including PoC and remediation.",
	}, wrapHandler(svc.getVulnAdapter))
}
