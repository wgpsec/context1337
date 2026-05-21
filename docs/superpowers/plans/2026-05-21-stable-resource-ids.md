# Stable Resource IDs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic `absec://` resource IDs to context1337 search results and allow detail/file tools to resolve resources by those IDs.

**Architecture:** Compute stable IDs at runtime from existing `resources` fields, avoiding schema migrations. Keep legacy `name/type/path` inputs working, but reject calls that provide both an ID and conflicting legacy parameters.

**Tech Stack:** Go 1.25, SQLite via `github.com/ncruces/go-sqlite3`, MCP Go SDK, standard `net/url`, existing Go test suite.

---

## File Structure

- Create: `internal/search/stable_id.go`
  - Owns stable ID formatting, parsing, type validation, and source-qualified lookup.
- Create: `internal/search/stable_id_test.go`
  - Tests ID construction, parsing failures, and source-collision lookup.
- Modify: `internal/mcp/unified.go`
  - Adds `id` to search summaries and detail results.
  - Resolves `GetInput.ID` for skill/vuln lookups.
  - Rejects ID/legacy parameter mismatches.
- Modify: `internal/mcp/getfile.go`
  - Adds `id` to file read input/results.
  - Resolves dict/payload files through stable IDs.
  - Rejects ID/legacy parameter mismatches.
- Modify: `internal/mcp/full_tools.go`
  - Adds `id` to full-mode get inputs and passes IDs through adapters.
  - Updates tool descriptions to mention stable IDs.
- Modify: `internal/mcp/unified_test.go`
  - Adds MCP search/get ID round-trip, mismatch, and agent-style ambiguity tests.
- Modify: `internal/mcp/getfile_test.go`
  - Adds file read ID round-trip and mismatch tests.
- Modify: `internal/mcp/full_tools_test.go`
  - Adds full-mode get adapter ID pass-through tests.
- Modify if needed: `internal/mcp/handler.go`
  - Updates lite-mode tool descriptions to say results include stable IDs and get/read tools prefer IDs.

---

### Task 1: Add search-layer stable ID helpers

**Files:**
- Create: `internal/search/stable_id.go`
- Create: `internal/search/stable_id_test.go`

- [ ] **Step 1: Write failing tests for stable ID helpers**

Create `internal/search/stable_id_test.go` with:

```go
package search

import (
	"strings"
	"testing"
)

func TestStableID(t *testing.T) {
	r := Resource{Source: "builtin", Type: "dict", Name: "Auth/password/Top100.txt"}
	got := StableID(r)
	want := "absec://builtin/dict/Auth%2Fpassword%2FTop100.txt"
	if got != want {
		t.Fatalf("StableID() = %q, want %q", got, want)
	}
}

func TestParseStableID(t *testing.T) {
	source, typ, key, err := ParseStableID("absec://nuclei/vuln/CVE-2021-44228")
	if err != nil {
		t.Fatalf("ParseStableID: %v", err)
	}
	if source != "nuclei" || typ != "vuln" || key != "CVE-2021-44228" {
		t.Fatalf("parsed = (%q, %q, %q), want (nuclei, vuln, CVE-2021-44228)", source, typ, key)
	}
}

func TestParseStableID_EscapedPath(t *testing.T) {
	source, typ, key, err := ParseStableID("absec://builtin/payload/XSS%2Fevents.txt")
	if err != nil {
		t.Fatalf("ParseStableID: %v", err)
	}
	if source != "builtin" || typ != "payload" || key != "XSS/events.txt" {
		t.Fatalf("parsed = (%q, %q, %q), want (builtin, payload, XSS/events.txt)", source, typ, key)
	}
}

func TestParseStableID_Invalid(t *testing.T) {
	tests := []string{
		"",
		"context1337://builtin/skill/sql-injection",
		"absec://builtin/skill",
		"absec://builtin/tool/nmap",
		"absec:///skill/sql-injection",
		"absec://builtin/skill/",
		"absec://builtin/dict/Auth/password/Top100.txt",
		"absec://builtin/dict/%zz",
	}
	for _, id := range tests {
		t.Run(id, func(t *testing.T) {
			_, _, _, err := ParseStableID(id)
			if err == nil {
				t.Fatalf("expected error for %q", id)
			}
		})
	}
}

func TestGetByStableID_SourceCollision(t *testing.T) {
	db := setupTestDB(t)
	for _, source := range []string{"builtin", "nuclei"} {
		if err := InsertResource(db, Resource{
			Type:        "vuln",
			Name:        "CVE-2021-44228",
			Source:      source,
			FilePath:    source + "/log4j.md",
			Category:    "middleware",
			Description: source + " log4j",
			Body:        source + " body",
		}); err != nil {
			t.Fatal(err)
		}
	}

	r, err := GetByStableID(db, "absec://nuclei/vuln/CVE-2021-44228")
	if err != nil {
		t.Fatalf("GetByStableID: %v", err)
	}
	if r == nil {
		t.Fatal("expected resource")
	}
	if r.Source != "nuclei" {
		t.Fatalf("Source = %q, want nuclei", r.Source)
	}
}

func TestGetByStableID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	r, err := GetByStableID(db, "absec://builtin/skill/missing")
	if err != nil {
		t.Fatalf("GetByStableID: %v", err)
	}
	if r != nil {
		t.Fatalf("resource = %#v, want nil", r)
	}
}

func TestGetByStableID_InvalidID(t *testing.T) {
	db := setupTestDB(t)
	_, err := GetByStableID(db, "not-an-absec-id")
	if err == nil {
		t.Fatal("expected invalid ID error")
	}
	if !strings.Contains(err.Error(), "invalid resource id") {
		t.Fatalf("error = %q, want invalid resource id", err.Error())
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/search -run 'StableID|ParseStableID|GetByStableID' -count=1
```

Expected: FAIL because `StableID`, `ParseStableID`, and `GetByStableID` are undefined.

- [ ] **Step 3: Implement stable ID helpers**

Create `internal/search/stable_id.go` with:

```go
package search

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
)

const stableIDPrefix = "absec://"

func StableID(r Resource) string {
	return stableIDPrefix + url.PathEscape(r.Source) + "/" + r.Type + "/" + url.PathEscape(r.Name)
}

func ParseStableID(id string) (source, typ, key string, err error) {
	rest, ok := strings.CutPrefix(id, stableIDPrefix)
	if !ok {
		return "", "", "", fmt.Errorf("invalid resource id %q: expected absec://{source}/{type}/{key}", id)
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid resource id %q: expected exactly source/type/key segments", id)
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", fmt.Errorf("invalid resource id %q: source, type, and key must be non-empty", id)
	}

	source, err = url.PathUnescape(parts[0])
	if err != nil {
		return "", "", "", fmt.Errorf("invalid resource id %q: bad source escape: %w", id, err)
	}
	key, err = url.PathUnescape(parts[2])
	if err != nil {
		return "", "", "", fmt.Errorf("invalid resource id %q: bad key escape: %w", id, err)
	}
	typ = parts[1]
	if !validResourceType(typ) {
		return "", "", "", fmt.Errorf("invalid resource id %q: unsupported resource type %q", id, typ)
	}
	if source == "" || key == "" {
		return "", "", "", fmt.Errorf("invalid resource id %q: source and key must be non-empty", id)
	}
	return source, typ, key, nil
}

func GetByStableID(db *sql.DB, id string) (*Resource, error) {
	source, typ, key, err := ParseStableID(id)
	if err != nil {
		return nil, err
	}

	var r Resource
	err = db.QueryRow(`
		SELECT id, type, COALESCE(name,''), COALESCE(source,''), COALESCE(file_path,''),
		       COALESCE(category,''), COALESCE(tags,''), COALESCE(mitre,''),
		       COALESCE(difficulty,''), COALESCE(description,''), COALESCE(body,''), COALESCE(metadata,'')
		FROM resources WHERE source=? AND type=? AND name=? LIMIT 1`, source, typ, key).Scan(
		&r.ID, &r.Type, &r.Name, &r.Source, &r.FilePath,
		&r.Category, &r.Tags, &r.Mitre, &r.Difficulty,
		&r.Description, &r.Body, &r.Metadata,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func validResourceType(typ string) bool {
	switch typ {
	case "skill", "dict", "payload", "vuln":
		return true
	default:
		return false
	}
}
```

- [ ] **Step 4: Run search tests**

Run:

```bash
go test ./internal/search -run 'StableID|ParseStableID|GetByStableID' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit search-layer helpers**

Run:

```bash
git add internal/search/stable_id.go internal/search/stable_id_test.go
git commit -m "feat: add stable resource ID helpers"
```

---

### Task 2: Add stable IDs to search summaries and detail lookup

**Files:**
- Modify: `internal/mcp/unified.go`
- Modify: `internal/mcp/unified_test.go`

- [ ] **Step 1: Write failing MCP tests for search result IDs and detail round-trip**

Append these tests to `internal/mcp/unified_test.go`:

```go
func TestSearch_ReturnsStableIDs(t *testing.T) {
	svc := setupUnifiedTest(t)
	result, err := svc.Search(context.Background(), SearchInput{Query: "SQL injection", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) == 0 {
		t.Fatal("expected results")
	}
	for _, item := range result.Items {
		if item.ID == "" {
			t.Fatalf("item %#v has empty ID", item)
		}
		if !strings.HasPrefix(item.ID, "absec://") {
			t.Fatalf("ID = %q, want absec:// prefix", item.ID)
		}
	}
}

func TestGet_WithStableID_SkillRoundTrip(t *testing.T) {
	svc := setupUnifiedTest(t)
	searchResult, err := svc.Search(context.Background(), SearchInput{Query: "SQL injection", Type: "skill", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(searchResult.Items) == 0 {
		t.Fatal("expected skill search result")
	}

	got, err := svc.Get(context.Background(), GetInput{ID: searchResult.Items[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != searchResult.Items[0].ID {
		t.Fatalf("ID = %q, want %q", got.ID, searchResult.Items[0].ID)
	}
	if got.Name != "sql-injection" || got.Type != "skill" || got.Source != "builtin" {
		t.Fatalf("got (%q, %q, %q), want (sql-injection, skill, builtin)", got.Name, got.Type, got.Source)
	}
}

func TestGet_WithStableID_VulnRoundTrip(t *testing.T) {
	svc := setupUnifiedTest(t)
	searchResult, err := svc.Search(context.Background(), SearchInput{Query: "JNDI", Type: "vuln", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(searchResult.Items) == 0 {
		t.Fatal("expected vuln search result")
	}

	got, err := svc.Get(context.Background(), GetInput{ID: searchResult.Items[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != searchResult.Items[0].ID {
		t.Fatalf("ID = %q, want %q", got.ID, searchResult.Items[0].ID)
	}
	if got.Name != "CVE-2021-44228" || got.Type != "vuln" || got.Source != "builtin" {
		t.Fatalf("got (%q, %q, %q), want (CVE-2021-44228, vuln, builtin)", got.Name, got.Type, got.Source)
	}
}

func TestGet_WithStableID_RejectsLegacyMismatch(t *testing.T) {
	svc := setupUnifiedTest(t)
	_, err := svc.Get(context.Background(), GetInput{
		ID:   "absec://builtin/skill/sql-injection",
		Type: "skill",
		Name: "xss-reflected",
	})
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("error = %q, want conflict", err.Error())
	}
}

func TestGet_WithStableID_SourceCollision_AgentAmbiguity(t *testing.T) {
	svc := setupUnifiedTest(t)
	_, err := svc.DB.Exec(`INSERT INTO resources (type,name,source,file_path,category,tags,description,body,metadata)
		VALUES ('vuln','CVE-2021-44228','nuclei','nuclei/http/cves/CVE-2021-44228.yaml','middleware','rce,jndi',
		'Nuclei Log4j template','nuclei yaml body',
		'{"severity":"CRITICAL","product":"Apache Log4j","vendor":"ProjectDiscovery"}')`)
	if err != nil {
		t.Fatal(err)
	}

	legacy, err := svc.Get(context.Background(), GetInput{Name: "CVE-2021-44228", Type: "vuln"})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Source == "" {
		t.Fatal("legacy lookup should return a source")
	}

	stable, err := svc.Get(context.Background(), GetInput{ID: "absec://nuclei/vuln/CVE-2021-44228"})
	if err != nil {
		t.Fatal(err)
	}
	if stable.Source != "nuclei" {
		t.Fatalf("stable Source = %q, want nuclei", stable.Source)
	}
	if stable.Vendor != "ProjectDiscovery" {
		t.Fatalf("stable Vendor = %q, want ProjectDiscovery", stable.Vendor)
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/mcp -run 'StableID|RoundTrip|SourceCollision|Mismatch|ReturnsStableIDs' -count=1
```

Expected: FAIL because `ResourceSummary.ID`, `GetInput.ID`, and `GetResult.ID` are not implemented.

- [ ] **Step 3: Update `internal/mcp/unified.go` structs**

Modify the relevant structs to include ID fields:

```go
type ResourceSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Source      string `json:"source"`
	Tags        string `json:"tags,omitempty"`
	Difficulty  string `json:"difficulty,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Product     string `json:"product,omitempty"`
	Vendor      string `json:"vendor,omitempty"`
	BodyLines   int    `json:"body_lines,omitempty"`
	RefCount    int    `json:"ref_count,omitempty"`
	Lines       int    `json:"lines,omitempty"`
}
```

```go
type GetInput struct {
	ID        string `json:"id,omitempty"         jsonschema:"Stable resource ID from search results, e.g. absec://builtin/skill/sql-injection. Preferred over name/type when available."`
	Name      string `json:"name,omitempty"       jsonschema:"Resource name (from search results)"`
	Type      string `json:"type,omitempty"       jsonschema:"Resource type: skill|vuln"`
	Depth     string `json:"depth,omitempty"      jsonschema:"Loading depth. Skill: metadata|summary|full (default summary). Vuln: brief|full (default brief). full includes references (skill) or PoC (vuln)."`
	RefOffset int    `json:"ref_offset,omitempty" jsonschema:"Reference pagination offset (default 0, skill depth=full only)"`
	RefLimit  int    `json:"ref_limit,omitempty"  jsonschema:"Max references to include (default 3, skill depth=full only)"`
}
```

```go
type GetResult struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Type            string           `json:"type"`
	Description     string           `json:"description"`
	Category        string           `json:"category"`
	Source          string           `json:"source"`
	Tags            string           `json:"tags,omitempty"`
	Difficulty      string           `json:"difficulty,omitempty"`
	Body            string           `json:"body,omitempty"`
	References      []SkillReference `json:"references,omitempty"`
	RefTotal        int              `json:"ref_total,omitempty"`
	Severity        string           `json:"severity,omitempty"`
	Product         string           `json:"product,omitempty"`
	Vendor          string           `json:"vendor,omitempty"`
	VersionAffected string           `json:"version_affected,omitempty"`
	Fingerprint     string           `json:"fingerprint,omitempty"`
}
```

- [ ] **Step 4: Compute IDs in search summaries**

Change `resourceToSummary` in `internal/mcp/unified.go` to set `ID`:

```go
func resourceToSummary(r search.Resource) ResourceSummary {
	s := ResourceSummary{
		ID: search.StableID(r),
		Name: r.Name, Type: r.Type, Description: r.Description,
		Category: r.Category, Source: r.Source,
		Tags: r.Tags, Difficulty: r.Difficulty,
	}
	if r.Type == "vuln" {
		s.Severity, s.Product, s.Vendor, _, _ = extractVulnMeta(r.Metadata)
	}
	if r.Type == "skill" || r.Type == "dict" || r.Type == "payload" {
		s.BodyLines, s.RefCount, s.Lines = extractSizeMeta(r.Metadata, r.Type)
	}
	return s
}
```

- [ ] **Step 5: Add ID resolution helpers for detail lookup**

Add these helper functions near `Get` in `internal/mcp/unified.go`:

```go
func (s *Service) resolveGetResource(in GetInput) (*search.Resource, error) {
	if in.ID == "" {
		if in.Type != "skill" && in.Type != "vuln" {
			return nil, fmt.Errorf("type must be skill or vuln (use read_security_file for dict/payload)")
		}
		r, err := search.GetByName(s.DB, in.Type, in.Name)
		if err != nil {
			return nil, err
		}
		if r == nil {
			return nil, fmt.Errorf(
				"%s %q not found; try search_security with broader keywords, or omit query to list all %ss",
				in.Type, in.Name, in.Type,
			)
		}
		return r, nil
	}

	r, err := search.GetByStableID(s.DB, in.ID)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("resource id %q not found; try search_security with broader keywords and use an id from the returned results", in.ID)
	}
	if r.Type != "skill" && r.Type != "vuln" {
		return nil, fmt.Errorf("resource id %q resolves to type=%s; use read_security_file for dict/payload", in.ID, r.Type)
	}
	if in.Type != "" && in.Type != r.Type {
		return nil, fmt.Errorf("resource id %q resolves to type=%s, which conflicts with type=%s", in.ID, r.Type, in.Type)
	}
	if in.Name != "" && in.Name != r.Name {
		return nil, fmt.Errorf("resource id %q resolves to name=%q, which conflicts with name=%q", in.ID, r.Name, in.Name)
	}
	return r, nil
}
```

- [ ] **Step 6: Use helper inside `Service.Get`**

Replace the initial validation/lookup block in `Service.Get` with:

```go
func (s *Service) Get(ctx context.Context, in GetInput) (*GetResult, error) {
	r, err := s.resolveGetResource(in)
	if err != nil {
		return nil, err
	}

	result := &GetResult{
		ID: search.StableID(*r),
		Name: r.Name, Type: r.Type, Description: r.Description,
		Category: r.Category, Source: r.Source,
		Tags: r.Tags, Difficulty: r.Difficulty,
	}

	switch r.Type {
```

Keep the existing switch body, but ensure every `in.Type` case switch becomes `r.Type` if it still references the resolved type. The rest of the existing skill/vuln logic stays unchanged.

- [ ] **Step 7: Run MCP tests**

Run:

```bash
go test ./internal/mcp -run 'Search_ReturnsStableIDs|Get_WithStableID|SourceCollision|Get_Skill|Get_Vuln|Get_InvalidType' -count=1
```

Expected: PASS.

- [ ] **Step 8: Commit MCP search/detail support**

Run:

```bash
git add internal/mcp/unified.go internal/mcp/unified_test.go
git commit -m "feat: support stable IDs for security details"
```

---

### Task 3: Add stable ID support to file reads

**Files:**
- Modify: `internal/mcp/getfile.go`
- Modify: `internal/mcp/getfile_test.go`

- [ ] **Step 1: Write failing file ID tests**

Append to `internal/mcp/getfile_test.go`:

```go
func TestGetFile_WithStableID_DictRoundTrip(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	dictDir := filepath.Join(svc.DataDir, "Dic", "Auth", "password")
	if err := os.MkdirAll(dictDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dictPath := filepath.Join(dictDir, "Top100.txt")
	if err := os.WriteFile(dictPath, []byte("pass1\npass2\npass3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DB.Exec("UPDATE resources SET file_path=? WHERE type='dict' AND name='Auth/password/Top100.txt'", dictPath); err != nil {
		t.Fatal(err)
	}

	searchResult, err := svc.Search(ctx, SearchInput{Type: "dict", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(searchResult.Items) == 0 {
		t.Fatal("expected dict search result")
	}

	got, err := svc.GetFile(ctx, GetFileInput{ID: searchResult.Items[0].ID, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != searchResult.Items[0].ID {
		t.Fatalf("ID = %q, want %q", got.ID, searchResult.Items[0].ID)
	}
	if got.Type != "dict" || got.Path != "Auth/password/Top100.txt" {
		t.Fatalf("got (%q, %q), want (dict, Auth/password/Top100.txt)", got.Type, got.Path)
	}
	if got.ReturnedLines != 2 {
		t.Fatalf("ReturnedLines = %d, want 2", got.ReturnedLines)
	}
}

func TestGetFile_WithStableID_PayloadRoundTrip(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	payloadDir := filepath.Join(svc.DataDir, "Payload", "XSS")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(payloadDir, "events.txt")
	if err := os.WriteFile(payloadPath, []byte("<img onerror>\n<svg onload>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DB.Exec("UPDATE resources SET file_path=? WHERE type='payload' AND name='XSS/events.txt'", payloadPath); err != nil {
		t.Fatal(err)
	}

	got, err := svc.GetFile(ctx, GetFileInput{ID: "absec://builtin/payload/XSS%2Fevents.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "absec://builtin/payload/XSS%2Fevents.txt" {
		t.Fatalf("ID = %q", got.ID)
	}
	if got.TotalLines != 2 {
		t.Fatalf("TotalLines = %d, want 2", got.TotalLines)
	}
}

func TestGetFile_WithStableID_RejectsLegacyMismatch(t *testing.T) {
	svc := setupUnifiedTest(t)
	_, err := svc.GetFile(context.Background(), GetFileInput{
		ID:   "absec://builtin/dict/Auth%2Fpassword%2FTop100.txt",
		Type: "dict",
		Path: "Other/passwords.txt",
	})
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("error = %q, want conflict", err.Error())
	}
}

func TestGetFile_WithStableID_RejectsWrongType(t *testing.T) {
	svc := setupUnifiedTest(t)
	_, err := svc.GetFile(context.Background(), GetFileInput{ID: "absec://builtin/skill/sql-injection"})
	if err == nil {
		t.Fatal("expected wrong type error")
	}
	if !strings.Contains(err.Error(), "type=skill") {
		t.Fatalf("error = %q, want type=skill", err.Error())
	}
}
```

Update imports in `internal/mcp/getfile_test.go` to include `strings`:

```go
import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/mcp -run 'GetFile_WithStableID' -count=1
```

Expected: FAIL because `GetFileInput.ID` and `GetFileResult.ID` do not exist.

- [ ] **Step 3: Update file input/result structs**

Modify `internal/mcp/getfile.go` structs:

```go
type GetFileInput struct {
	ID     string `json:"id,omitempty"     jsonschema:"Stable resource ID from search results, e.g. absec://builtin/dict/Auth%2Fpassword%2FTop100.txt. Preferred over path/type when available."`
	Path   string `json:"path,omitempty"   jsonschema:"Relative file path from search results (e.g. Auth/password/Top100.txt)"`
	Type   string `json:"type,omitempty"   jsonschema:"Resource type: dict|payload"`
	Offset int    `json:"offset,omitempty" jsonschema:"Line offset for pagination (default 0)"`
	Limit  int    `json:"limit,omitempty"  jsonschema:"Max lines to return (default 200)"`
}

type GetFileResult struct {
	ID            string `json:"id,omitempty"`
	Path          string `json:"path"`
	Type          string `json:"type"`
	TotalLines    int    `json:"total_lines"`
	ReturnedLines int    `json:"returned_lines"`
	Content       string `json:"content"`
}
```

- [ ] **Step 4: Add file resolution helper**

Add to `internal/mcp/getfile.go`:

```go
func (s *Service) resolveFileResource(in GetFileInput) (id, typ, path, absPath string, err error) {
	if in.ID == "" {
		baseDir, err := fileBaseDir(in.Type)
		if err != nil {
			return "", "", "", "", err
		}
		clean := filepath.Clean(in.Path)
		if strings.Contains(clean, "..") {
			return "", "", "", "", fmt.Errorf("invalid path")
		}
		return "", in.Type, clean, filepath.Join(s.DataDir, baseDir, clean), nil
	}

	r, err := search.GetByStableID(s.DB, in.ID)
	if err != nil {
		return "", "", "", "", err
	}
	if r == nil {
		return "", "", "", "", fmt.Errorf("resource id %q not found; try search_security with broader keywords and use an id from the returned results", in.ID)
	}
	if r.Type != "dict" && r.Type != "payload" {
		return "", "", "", "", fmt.Errorf("resource id %q resolves to type=%s; use get_security_detail for skill/vuln", in.ID, r.Type)
	}
	if in.Type != "" && in.Type != r.Type {
		return "", "", "", "", fmt.Errorf("resource id %q resolves to type=%s, which conflicts with type=%s", in.ID, r.Type, in.Type)
	}
	if in.Path != "" && in.Path != r.Name {
		return "", "", "", "", fmt.Errorf("resource id %q resolves to path=%q, which conflicts with path=%q", in.ID, r.Name, in.Path)
	}
	absPath = r.FilePath
	if absPath == "" {
		baseDir, err := fileBaseDir(r.Type)
		if err != nil {
			return "", "", "", "", err
		}
		absPath = filepath.Join(s.DataDir, baseDir, r.Name)
	}
	return search.StableID(*r), r.Type, r.Name, absPath, nil
}

func fileBaseDir(typ string) (string, error) {
	switch typ {
	case "dict":
		return "Dic", nil
	case "payload":
		return "Payload", nil
	default:
		return "", fmt.Errorf("type must be dict or payload (use get for skill/tool)")
	}
}
```

Also add the search import to `internal/mcp/getfile.go`:

```go
import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/wgpsec/context1337/internal/search"
	"github.com/wgpsec/context1337/internal/storage"
)
```

- [ ] **Step 5: Use helper in `Service.GetFile`**

Replace `Service.GetFile` body with:

```go
func (s *Service) GetFile(ctx context.Context, in GetFileInput) (*GetFileResult, error) {
	id, typ, path, absPath, err := s.resolveFileResource(in)
	if err != nil {
		return nil, err
	}
	if in.Limit <= 0 {
		in.Limit = 200
	}

	content, total, err := storage.ReadFileLines(absPath, in.Offset, in.Limit)
	if err != nil {
		return nil, fmt.Errorf("read %s %q: %w", typ, path, err)
	}
	returned := total - in.Offset
	if in.Limit > 0 && returned > in.Limit {
		returned = in.Limit
	}
	return &GetFileResult{
		ID: id, Path: path, Type: typ,
		TotalLines: total, ReturnedLines: returned, Content: content,
	}, nil
}
```

- [ ] **Step 6: Run file tests**

Run:

```bash
go test ./internal/mcp -run 'GetFile' -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit file ID support**

Run:

```bash
git add internal/mcp/getfile.go internal/mcp/getfile_test.go
git commit -m "feat: support stable IDs for file reads"
```

---

### Task 4: Thread stable IDs through full-mode adapters and tool descriptions

**Files:**
- Modify: `internal/mcp/full_tools.go`
- Modify: `internal/mcp/full_tools_test.go`
- Modify: `internal/mcp/handler.go`

- [ ] **Step 1: Write failing full-mode adapter tests**

Append to `internal/mcp/full_tools_test.go`:

```go
func TestGetSkillAdapter_WithID(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.getSkillAdapter(context.Background(), GetSkillInput{ID: "absec://builtin/skill/sql-injection"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ID != "absec://builtin/skill/sql-injection" {
		t.Fatalf("ID = %q", res.ID)
	}
	if res.Name != "sql-injection" || res.Type != "skill" {
		t.Fatalf("got (%q, %q), want (sql-injection, skill)", res.Name, res.Type)
	}
}

func TestGetVulnAdapter_WithID(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.getVulnAdapter(context.Background(), GetVulnInput{ID: "absec://builtin/vuln/CVE-2021-44228"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ID != "absec://builtin/vuln/CVE-2021-44228" {
		t.Fatalf("ID = %q", res.ID)
	}
	if res.Name != "CVE-2021-44228" || res.Type != "vuln" {
		t.Fatalf("got (%q, %q), want (CVE-2021-44228, vuln)", res.Name, res.Type)
	}
}

func TestGetDictAdapter_WithID(t *testing.T) {
	svc := setupUnifiedTest(t)
	dictDir := filepath.Join(svc.DataDir, "Dic", "Auth", "password")
	if err := os.MkdirAll(dictDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dictPath := filepath.Join(dictDir, "Top100.txt")
	if err := os.WriteFile(dictPath, []byte("pass1\npass2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DB.Exec("UPDATE resources SET file_path=? WHERE type='dict' AND name='Auth/password/Top100.txt'", dictPath); err != nil {
		t.Fatal(err)
	}

	res, err := svc.getDictAdapter(context.Background(), GetDictInput{ID: "absec://builtin/dict/Auth%2Fpassword%2FTop100.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ID != "absec://builtin/dict/Auth%2Fpassword%2FTop100.txt" {
		t.Fatalf("ID = %q", res.ID)
	}
	if res.TotalLines != 2 {
		t.Fatalf("TotalLines = %d, want 2", res.TotalLines)
	}
}

func TestGetPayloadAdapter_WithID(t *testing.T) {
	svc := setupUnifiedTest(t)
	payloadDir := filepath.Join(svc.DataDir, "Payload", "XSS")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(payloadDir, "events.txt")
	if err := os.WriteFile(payloadPath, []byte("<img onerror>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DB.Exec("UPDATE resources SET file_path=? WHERE type='payload' AND name='XSS/events.txt'", payloadPath); err != nil {
		t.Fatal(err)
	}

	res, err := svc.getPayloadAdapter(context.Background(), GetPayloadInput{ID: "absec://builtin/payload/XSS%2Fevents.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ID != "absec://builtin/payload/XSS%2Fevents.txt" {
		t.Fatalf("ID = %q", res.ID)
	}
	if res.TotalLines != 1 {
		t.Fatalf("TotalLines = %d, want 1", res.TotalLines)
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/mcp -run 'Adapter_WithID' -count=1
```

Expected: FAIL because full-mode input structs do not expose `ID` yet.

- [ ] **Step 3: Update full-mode input structs**

Modify get input structs in `internal/mcp/full_tools.go`:

```go
type GetSkillInput struct {
	ID    string `json:"id,omitempty"    jsonschema:"Stable resource ID from search_skill/list_skills results. Preferred over name when available."`
	Name  string `json:"name,omitempty"  jsonschema:"Skill name (from search results)"`
	Depth string `json:"depth,omitempty" jsonschema:"Loading depth: metadata|summary|full (default summary). full includes references."`
}

type GetDictInput struct {
	ID     string `json:"id,omitempty"     jsonschema:"Stable resource ID from search_dicts/list_dicts results. Preferred over path when available."`
	Path   string `json:"path,omitempty"   jsonschema:"Relative file path from search results (e.g. Auth/password/Top100.txt)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Line offset for pagination (default 0)"`
	Limit  int    `json:"limit,omitempty"  jsonschema:"Max lines to return (default 200)"`
}

type GetPayloadInput struct {
	ID     string `json:"id,omitempty"     jsonschema:"Stable resource ID from search_payload/list_payloads results. Preferred over path when available."`
	Path   string `json:"path,omitempty"   jsonschema:"Relative file path from search results (e.g. XSS/xss-payload-list.txt)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Line offset for pagination (default 0)"`
	Limit  int    `json:"limit,omitempty"  jsonschema:"Max lines to return (default 200)"`
}

type GetVulnInput struct {
	ID    string `json:"id,omitempty"    jsonschema:"Stable resource ID from search_vuln/list_vulns results. Preferred over name when available."`
	Name  string `json:"name,omitempty"  jsonschema:"Vulnerability ID (CVE/CNVD from search results)"`
	Depth string `json:"depth,omitempty" jsonschema:"Loading depth: brief|full (default brief). full includes PoC and remediation."`
}
```

- [ ] **Step 4: Pass IDs through adapters**

Modify adapter methods in `internal/mcp/full_tools.go`:

```go
func (s *Service) getSkillAdapter(ctx context.Context, in GetSkillInput) (*GetResult, error) {
	return s.Get(ctx, GetInput{ID: in.ID, Name: in.Name, Type: "skill", Depth: in.Depth})
}

func (s *Service) getDictAdapter(ctx context.Context, in GetDictInput) (*GetFileResult, error) {
	return s.GetFile(ctx, GetFileInput{ID: in.ID, Path: in.Path, Type: "dict", Offset: in.Offset, Limit: in.Limit})
}

func (s *Service) getPayloadAdapter(ctx context.Context, in GetPayloadInput) (*GetFileResult, error) {
	return s.GetFile(ctx, GetFileInput{ID: in.ID, Path: in.Path, Type: "payload", Offset: in.Offset, Limit: in.Limit})
}

func (s *Service) getVulnAdapter(ctx context.Context, in GetVulnInput) (*GetResult, error) {
	return s.Get(ctx, GetInput{ID: in.ID, Name: in.Name, Type: "vuln", Depth: in.Depth})
}
```

- [ ] **Step 5: Update lite and full tool descriptions**

In `internal/mcp/handler.go`, update descriptions:

```go
Name:        "search_security",
Description: "Search the AboutSecurity penetration testing knowledge base. Covers: exploit techniques (SQL injection, XSS, SSRF, RCE...), password/bruteforce wordlists, and attack payloads. IMPORTANT: use space-separated keywords, NOT natural language sentences. Good: \"域控 持久化\", \"file upload webshell\", \"提权 linux\", \"应急响应\". Bad: \"拿到域管后怎么维持权限\". To search vulnerabilities, you MUST specify type=\"vuln\" explicitly — vulnerabilities are excluded from default search to avoid polluting technique-oriented results. Vuln search supports additional filters: severity (CRITICAL/HIGH/MEDIUM/LOW) and product. Params: query (optional keyword — omit to list all), type (optional: skill|dict|payload|vuln — omit to search all non-vuln types), category (optional), difficulty (optional, skill only), severity (optional, vuln only), product (optional, vuln only), offset (default 0), limit (default 10, vuln default 50). Returns results with stable id fields; pass those ids to get_security_detail or read_security_file to avoid ambiguous name/path lookups.",
```

```go
Name:        "get_security_detail",
Description: "Get detailed penetration testing knowledge for a skill or vulnerability. Prefer id from search_security results; legacy name+type remains supported. Params: id (optional stable resource ID), name (from search results), type (skill|vuln), depth (optional — skill: metadata|summary|full, default summary; vuln: brief|full, default brief). For skills with many references, depth=full returns paginated references: use ref_offset (default 0) and ref_limit (default 3) to page through them. The response includes ref_total showing the total number of references available.",
```

```go
Name:        "read_security_file",
Description: "Read security dictionary (wordlists/passwords) or attack payload file content with line-level pagination. Prefer id from search_security results; legacy path+type remains supported. Params: id (optional stable resource ID), path (from search results, e.g. Auth/password/Top100.txt), type (dict|payload), offset (default 0 lines), limit (default 200 lines). Returns file content with total_lines count.",
```

In `internal/mcp/full_tools.go`, update the four get descriptions to say `id` is preferred. Keep wording concise:

```go
Description: "Get detailed penetration testing skill content. Prefer id from search_skill/list_skills results; legacy name remains supported. Returns exploit technique documentation including description, body, and optional references. Set depth=full to include reference files.",
```

```go
Description: "Read password dictionary or wordlist file content with line-level pagination. Prefer id from search_dicts/list_dicts results; legacy path remains supported. Returns file lines with total line count.",
```

```go
Description: "Read attack payload file content with line-level pagination. Prefer id from search_payload/list_payloads results; legacy path remains supported. Returns payload strings with total line count.",
```

```go
Description: "Get vulnerability detail. Prefer id from search_vuln/list_vulns results; legacy name remains supported. depth=\"brief\" returns structured fields and description. depth=\"full\" returns complete content including PoC and remediation.",
```

- [ ] **Step 6: Run adapter tests**

Run:

```bash
go test ./internal/mcp -run 'Adapter' -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit adapter and description updates**

Run:

```bash
git add internal/mcp/full_tools.go internal/mcp/full_tools_test.go internal/mcp/handler.go
git commit -m "feat: expose stable IDs in MCP tools"
```

---

### Task 5: Run full validation and repeated value tests

**Files:**
- Modify only if failures reveal required fixes in files changed by previous tasks.

- [ ] **Step 1: Run full Go test suite**

Run:

```bash
go test ./...
```

Expected: PASS for all packages.

- [ ] **Step 2: Run focused repeated tests**

Run:

```bash
go test -run 'StableID|RoundTrip|InvalidID|SourceCollision|Ambiguity|ReturnsStableIDs|GetFile_WithStableID|Adapter_WithID' ./internal/search ./internal/mcp -count=100
```

Expected: PASS repeatedly. This validates ID determinism, parsing, source disambiguation, round-trip behavior, and adapter pass-through.

- [ ] **Step 3: Run full-suite repeated validation**

Run:

```bash
for i in $(seq 1 25); do go test ./... || exit 1; done
```

Expected: all 25 runs PASS.

- [ ] **Step 4: Run race detector**

Run:

```bash
go test -race ./...
```

Expected: PASS. If this is too slow locally, report timing and run at least `go test -race ./internal/search ./internal/mcp` before requesting review.

- [ ] **Step 5: Inspect final diff**

Run:

```bash
git status --short
git diff --stat HEAD~3..HEAD
git diff HEAD~3..HEAD -- internal/search internal/mcp
```

Expected: only stable-ID implementation and tests changed, plus the already-committed spec/plan files if intentionally included.

- [ ] **Step 6: Commit any validation fixes**

If Step 1-4 required fixes, commit them:

```bash
git add internal/search internal/mcp
git commit -m "test: validate stable resource IDs"
```

If no fixes were needed, skip this commit.

---

### Task 6: Request review and prepare completion handoff

**Files:**
- No code changes unless review finds issues.

- [ ] **Step 1: Use the requesting-review skill**

Invoke:

```text
superpowers:requesting-code-review
```

Ask the reviewer to focus on:

- ID parsing safety and edge cases.
- Backward compatibility of legacy `name/type/path` inputs.
- Whether mismatch errors are clear.
- Whether source-collision tests actually prove the intended value.

- [ ] **Step 2: Address review feedback**

If feedback requests changes, use:

```text
superpowers:receiving-code-review
```

Then make minimal targeted fixes, rerun:

```bash
go test ./...
go test -run 'StableID|RoundTrip|InvalidID|SourceCollision|Ambiguity|ReturnsStableIDs|GetFile_WithStableID|Adapter_WithID' ./internal/search ./internal/mcp -count=100
```

- [ ] **Step 3: Verify before claiming completion**

Invoke:

```text
superpowers:verification-before-completion
```

Then report exact command outputs from the final verification run.

- [ ] **Step 4: Finish branch**

Invoke:

```text
superpowers:finishing-a-development-branch
```

Offer the user merge/PR/keep-branch options.

---

## Self-Review

### Spec coverage

- Deterministic IDs in search/list results: Task 2.
- `get_security_detail(id=...)`: Task 2.
- `read_security_file(id=...)`: Task 3.
- Legacy compatibility: Tasks 2 and 3 keep old paths and rerun existing tests.
- Reject conflicting ID/legacy params: Tasks 2 and 3.
- Source collision / Agent-style value test: Task 2.
- Repeated tests: Task 5.
- No schema migration: Task 1 computes IDs at runtime and uses existing `source/type/name` fields.

### Placeholder scan

No intentionally deferred implementation details remain. Every code-changing step includes concrete code or exact replacement snippets.

### Type consistency

- Stable ID API is `search.StableID`, `search.ParseStableID`, and `search.GetByStableID` throughout.
- MCP input fields are `ID string json:"id,omitempty"` for both detail and file tools.
- Result fields are `ID string json:"id"` for `GetResult` and `ID string json:"id,omitempty"` for `GetFileResult`.
