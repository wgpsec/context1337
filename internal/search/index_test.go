package search

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/Esonhugh/context1337/internal/storage"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestInsertResource(t *testing.T) {
	db := setupTestDB(t)
	err := InsertResource(db, Resource{
		Type:        "skill",
		Name:        "sql-injection",
		Source:      "builtin",
		FilePath:    "skills/sql-injection/SKILL.md",
		Category:    "exploit",
		Tags:        "sqli,owasp,web",
		Description: "SQL Injection attack techniques",
		Body:        "SQL injection is a common web security vulnerability",
	})
	if err != nil {
		t.Fatalf("InsertResource: %v", err)
	}
}

func TestSearch_ByKeyword(t *testing.T) {
	db := setupTestDB(t)

	InsertResource(db, Resource{
		Type: "skill", Name: "sql-injection", Source: "builtin",
		FilePath: "skills/sql-injection/SKILL.md", Category: "exploit",
		Tags: "sqli,owasp", Description: "SQL Injection techniques",
		Body: "SQL injection attack details",
	})
	InsertResource(db, Resource{
		Type: "skill", Name: "xss-reflected", Source: "builtin",
		FilePath: "skills/xss-reflected/SKILL.md", Category: "exploit",
		Tags: "xss,owasp", Description: "Reflected XSS attacks",
		Body: "Reflected cross-site scripting attack",
	})

	results, err := Search(db, SearchQuery{
		Query: "SQL Injection",
		Type:  "skill",
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected results, got none")
	}
	if results[0].Name != "sql-injection" {
		t.Errorf("top result = %q, want sql-injection", results[0].Name)
	}
}

func TestSearch_WithCategoryFilter(t *testing.T) {
	db := setupTestDB(t)

	InsertResource(db, Resource{
		Type: "skill", Name: "nmap-scan", Source: "builtin",
		FilePath: "skills/nmap/SKILL.md", Category: "recon",
		Tags: "scan", Description: "Nmap scanning",
		Body: "Network scanning with nmap",
	})
	InsertResource(db, Resource{
		Type: "skill", Name: "sql-injection", Source: "builtin",
		FilePath: "skills/sqli/SKILL.md", Category: "exploit",
		Tags: "sqli", Description: "SQL Injection",
		Body: "SQL Injection techniques",
	})

	results, err := Search(db, SearchQuery{
		Query:    "scan",
		Type:     "skill",
		Category: "recon",
		Limit:    10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Name != "nmap-scan" {
		t.Errorf("expected only nmap-scan with category filter, got %v", results)
	}
}

func TestListByType_ReturnsTotalAndOffset(t *testing.T) {
	db := setupTestDB(t)
	for _, name := range []string{"skill-a", "skill-b", "skill-c"} {
		if err := InsertResource(db, Resource{
			Type: "skill", Name: name, Source: "builtin",
			Category: "exploit", Description: name,
		}); err != nil {
			t.Fatal(err)
		}
	}
	result, err := ListByType(db, ListQuery{Type: "skill", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 3 {
		t.Errorf("total = %d, want 3", result.Total)
	}
	if len(result.Items) != 2 {
		t.Errorf("items = %d, want 2", len(result.Items))
	}
	result2, err := ListByType(db, ListQuery{Type: "skill", Offset: 2, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if result2.Total != 3 {
		t.Errorf("total with offset = %d, want 3", result2.Total)
	}
	if len(result2.Items) != 1 {
		t.Errorf("items with offset = %d, want 1", len(result2.Items))
	}
}

func TestListByType_DifficultyFilter(t *testing.T) {
	db := setupTestDB(t)
	InsertResource(db, Resource{
		Type: "skill", Name: "easy-one", Source: "builtin",
		Category: "exploit", Difficulty: "easy", Description: "easy skill",
	})
	InsertResource(db, Resource{
		Type: "skill", Name: "hard-one", Source: "builtin",
		Category: "exploit", Difficulty: "hard", Description: "hard skill",
	})
	result, err := ListByType(db, ListQuery{Type: "skill", Difficulty: "easy", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 {
		t.Errorf("total = %d, want 1", result.Total)
	}
	if len(result.Items) != 1 || result.Items[0].Name != "easy-one" {
		t.Errorf("unexpected items: %v", result.Items)
	}
}
