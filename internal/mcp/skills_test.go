package mcp

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Esonhugh/context1337/internal/search"
	"github.com/Esonhugh/context1337/internal/storage"
)

func setupTestService(t *testing.T) *Service {
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
		Body:        "SQL injection is a common web security vulnerability.\n\n## Steps\n1. Find injection points\n2. Extract data",
	})
	search.InsertResource(db, search.Resource{
		Type: "skill", Name: "xss-reflected", Source: "builtin",
		FilePath: "skills/xss-reflected/SKILL.md", Category: "exploit",
		Tags: "xss,owasp", Difficulty: "easy",
		Description: "Reflected XSS attacks",
		Body:        "Reflected cross-site scripting attack techniques",
	})

	return &Service{DB: db, DataDir: dir}
}

func TestListSkills_Paginated(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	result, err := svc.ListSkills(ctx, ListSkillsInput{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 2 {
		t.Errorf("total = %d, want 2", result.Total)
	}
	if len(result.Items) != 1 {
		t.Errorf("items = %d, want 1", len(result.Items))
	}
}

func TestListSkills_DifficultyFilter(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	result, err := svc.ListSkills(ctx, ListSkillsInput{Difficulty: "easy", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 {
		t.Errorf("total = %d, want 1", result.Total)
	}
	if len(result.Items) != 1 || result.Items[0].Name != "xss-reflected" {
		t.Errorf("expected xss-reflected only, got %v", result.Items)
	}
}

func TestSearchSkill(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	result, err := svc.SearchSkill(ctx, SearchSkillInput{Query: "SQL injection", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) == 0 {
		t.Fatal("expected results")
	}
	if result.Items[0].Name != "sql-injection" {
		t.Errorf("top = %q, want sql-injection", result.Items[0].Name)
	}
}

func TestSearchSkill_Paginated(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	result, err := svc.SearchSkill(ctx, SearchSkillInput{Query: "attack", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total < 1 {
		t.Errorf("total = %d, want >= 1", result.Total)
	}
	if len(result.Items) != 1 {
		t.Errorf("items = %d, want 1", len(result.Items))
	}
}

func TestSearchSkill_CategoryFilter(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	result, err := svc.SearchSkill(ctx, SearchSkillInput{
		Query: "attack", Category: "exploit", Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range result.Items {
		if r.Category != "exploit" {
			t.Errorf("result %q has category %q, want exploit", r.Name, r.Category)
		}
	}
}

func TestGetSkill_Summary(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	result, err := svc.GetSkill(ctx, GetSkillInput{Name: "sql-injection", Depth: "summary"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "sql-injection" {
		t.Errorf("name = %q", result.Name)
	}
	if result.Body == "" {
		t.Error("summary depth should include body")
	}
}

func TestGetSkill_MetadataOnly(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	result, err := svc.GetSkill(ctx, GetSkillInput{Name: "sql-injection", Depth: "metadata"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Body != "" {
		t.Error("metadata depth should not include body")
	}
}

func TestGetSkill_NotFound(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	_, err := svc.GetSkill(ctx, GetSkillInput{Name: "nonexistent"})
	if err == nil {
		t.Fatal("expected error for nonexistent skill")
	}
}
