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
