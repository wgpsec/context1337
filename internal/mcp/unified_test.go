package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/wgpsec/context1337/internal/search"
	"github.com/wgpsec/context1337/internal/storage"
)

func setupUnifiedTest(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := storage.OpenDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	search.InsertResource(db, search.Resource{
		Type: "skill", Name: "sql-injection", Source: "builtin",
		FilePath: "skills/sql-injection/SKILL.md", Category: "exploit",
		Tags: "sqli,owasp,web", Difficulty: "medium",
		Description: "SQL Injection attack techniques",
		Body:        "SQL injection is a common web vulnerability",
	})
	search.InsertResource(db, search.Resource{
		Type: "skill", Name: "xss-reflected", Source: "builtin",
		FilePath: "skills/xss-reflected/SKILL.md", Category: "exploit",
		Tags: "xss,owasp", Difficulty: "easy",
		Description: "Reflected XSS attacks",
		Body:        "Reflected cross-site scripting techniques",
	})
	search.InsertResource(db, search.Resource{
		Type: "dict", Name: "Auth/password/Top100.txt", Source: "builtin",
		Category: "auth", Description: "Common passwords top 100",
	})
	search.InsertResource(db, search.Resource{
		Type: "payload", Name: "XSS/events.txt", Source: "builtin",
		Category: "xss", Description: "XSS event handler payloads",
	})
	search.InsertResource(db, search.Resource{
		Type: "tool", Name: "nmap", Source: "builtin",
		Category: "scan", Description: "Port scanner",
		Metadata: `{"binary":"nmap","homepage":"https://nmap.org"}`,
	})

	// Insert a vuln resource
	db.Exec(`INSERT INTO resources (type,name,source,file_path,category,tags,description,body,metadata)
		VALUES ('vuln','CVE-2021-44228','builtin','test/vuln.md','middleware','rce,jndi',
		'JNDI injection leads to RCE','## PoC\ntest payload',
		'{"severity":"CRITICAL","product":"Apache Log4j","vendor":"Apache","version_affected":"<2.17.0","fingerprint":"header=X-Log4j"}')`)

	return &Service{DB: db, DataDir: dir}
}

func TestSearch_Keyword(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Query: "SQL injection", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) == 0 {
		t.Fatal("expected results")
	}
	if result.Items[0].Name != "sql-injection" {
		t.Errorf("top = %q, want sql-injection", result.Items[0].Name)
	}
	if result.Items[0].Type != "skill" {
		t.Errorf("type = %q, want skill", result.Items[0].Type)
	}
}

func TestSearch_TypeFilter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Query: "port", Type: "tool", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range result.Items {
		if item.Type != "tool" {
			t.Errorf("item %q has type %q, want tool", item.Name, item.Type)
		}
	}
}

func TestSearch_EmptyQuery_ListAll(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total < 5 {
		t.Errorf("total = %d, want >= 5 (all resource types)", result.Total)
	}
}

func TestSearch_EmptyQuery_TypeFilter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Type: "skill", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 2 {
		t.Errorf("total = %d, want 2", result.Total)
	}
	for _, item := range result.Items {
		if item.Type != "skill" {
			t.Errorf("item %q has type %q, want skill", item.Name, item.Type)
		}
	}
}

func TestSearch_CategoryFilter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Type: "skill", Category: "exploit", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range result.Items {
		if item.Category != "exploit" {
			t.Errorf("item %q has category %q, want exploit", item.Name, item.Category)
		}
	}
}

func TestSearch_ToolMetadata(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Query: "nmap", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) == 0 {
		t.Fatal("expected nmap result")
	}
	found := false
	for _, item := range result.Items {
		if item.Name == "nmap" {
			found = true
			if item.Binary != "nmap" {
				t.Errorf("binary = %q, want nmap", item.Binary)
			}
			if item.Homepage != "https://nmap.org" {
				t.Errorf("homepage = %q", item.Homepage)
			}
		}
	}
	if !found {
		t.Error("nmap not in results")
	}
}

func TestGet_Skill_Summary(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Get(ctx, GetInput{Name: "sql-injection", Type: "skill"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "sql-injection" {
		t.Errorf("name = %q", result.Name)
	}
	if result.Type != "skill" {
		t.Errorf("type = %q", result.Type)
	}
	if result.Body == "" {
		t.Error("summary depth should include body")
	}
}

func TestGet_Skill_Metadata(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Get(ctx, GetInput{Name: "sql-injection", Type: "skill", Depth: "metadata"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Body != "" {
		t.Error("metadata depth should not include body")
	}
}

func TestGet_Skill_Full_WithReferences(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()

	skillDir := filepath.Join(svc.DataDir, "skills", "exploit", "sql-injection")
	os.MkdirAll(filepath.Join(skillDir, "references"), 0o755)
	os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: sql-injection\n---\nbody"), 0o644)
	os.WriteFile(filepath.Join(skillDir, "references", "advanced.md"), []byte("# Advanced\nSQL techniques"), 0o644)

	svc.DB.Exec("UPDATE resources SET file_path=? WHERE name='sql-injection'",
		filepath.Join(skillDir, "SKILL.md"))

	result, err := svc.Get(ctx, GetInput{Name: "sql-injection", Type: "skill", Depth: "full"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.References) != 1 {
		t.Fatalf("references = %d, want 1", len(result.References))
	}
}

func TestGet_Tool(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()

	toolDir := filepath.Join(svc.DataDir, "Tools")
	os.MkdirAll(toolDir, 0o755)
	toolPath := filepath.Join(toolDir, "nmap.yaml")
	os.WriteFile(toolPath, []byte("id: nmap\nbinary: nmap\n"), 0o644)

	svc.DB.Exec("UPDATE resources SET file_path=? WHERE name='nmap'", toolPath)

	result, err := svc.Get(ctx, GetInput{Name: "nmap", Type: "tool"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Config == "" {
		t.Error("expected config content")
	}
	if result.Homepage != "https://nmap.org" {
		t.Errorf("homepage = %q", result.Homepage)
	}
}

func TestGet_NotFound(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	_, err := svc.Get(ctx, GetInput{Name: "nonexistent", Type: "skill"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGet_InvalidType(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	_, err := svc.Get(ctx, GetInput{Name: "test", Type: "dict"})
	if err == nil {
		t.Fatal("expected error for dict type")
	}
}

func TestSearch_VulnExcludedByDefault(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.Search(context.Background(), SearchInput{Query: "injection", Limit: 20})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	for _, item := range res.Items {
		if item.Type == "vuln" {
			t.Errorf("vuln should not appear in default search, got %q", item.Name)
		}
	}
}

func TestSearch_VulnWithExplicitType(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.Search(context.Background(), SearchInput{Query: "JNDI injection", Type: "vuln", Limit: 20})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Total == 0 {
		t.Fatal("expected vuln results with type=vuln")
	}
	if res.Items[0].Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL", res.Items[0].Severity)
	}
	if res.Items[0].Product != "Apache Log4j" {
		t.Errorf("Product = %q", res.Items[0].Product)
	}
}

func TestSearch_VulnSeverityFilter(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.Search(context.Background(), SearchInput{
		Type: "vuln", Severity: "CRITICAL", Limit: 20,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Total != 1 {
		t.Errorf("total = %d, want 1", res.Total)
	}
}

func TestGet_Vuln_Brief(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.Get(context.Background(), GetInput{Name: "CVE-2021-44228", Type: "vuln"})
	if err != nil {
		t.Fatalf("Get vuln: %v", err)
	}
	if res.Severity != "CRITICAL" {
		t.Errorf("Severity = %q", res.Severity)
	}
	if res.Product != "Apache Log4j" {
		t.Errorf("Product = %q", res.Product)
	}
	if res.Body != "" {
		t.Error("brief mode should not include body")
	}
}

func TestSearch_SkillSizeMetadata(t *testing.T) {
	svc := setupUnifiedTest(t)
	svc.DB.Exec(`UPDATE resources SET metadata='{"body_lines":150,"ref_count":2}' WHERE name='sql-injection'`)

	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Query: "SQL injection", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) == 0 {
		t.Fatal("expected results")
	}
	found := false
	for _, item := range result.Items {
		if item.Name == "sql-injection" {
			found = true
			if item.BodyLines != 150 {
				t.Errorf("BodyLines = %d, want 150", item.BodyLines)
			}
			if item.RefCount != 2 {
				t.Errorf("RefCount = %d, want 2", item.RefCount)
			}
		}
	}
	if !found {
		t.Error("sql-injection not in results")
	}
}

func TestSearch_DictSizeMetadata(t *testing.T) {
	svc := setupUnifiedTest(t)
	svc.DB.Exec(`UPDATE resources SET metadata='{"lines":586}' WHERE name='Auth/password/Top100.txt'`)

	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Query: "password", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range result.Items {
		if item.Name == "Auth/password/Top100.txt" {
			found = true
			if item.Lines != 586 {
				t.Errorf("Lines = %d, want 586", item.Lines)
			}
		}
	}
	if !found {
		t.Error("dict not in results")
	}
}

func TestGet_Vuln_Full(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.Get(context.Background(), GetInput{Name: "CVE-2021-44228", Type: "vuln", Depth: "full"})
	if err != nil {
		t.Fatalf("Get vuln full: %v", err)
	}
	if res.Body == "" {
		t.Error("full mode should include body")
	}
	if res.Fingerprint != "header=X-Log4j" {
		t.Errorf("Fingerprint = %q", res.Fingerprint)
	}
}
