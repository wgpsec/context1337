package search

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/wgpsec/context1337/internal/storage"
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

	results, _, err := Search(db, SearchQuery{
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

	results, _, err := Search(db, SearchQuery{
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

func TestListByType_AllTypes(t *testing.T) {
	db := setupTestDB(t)
	InsertResource(db, Resource{
		Type: "skill", Name: "test-skill", Source: "builtin",
		Category: "exploit", Description: "a skill",
	})
	InsertResource(db, Resource{
		Type: "dict", Name: "test-dict", Source: "builtin",
		Category: "password", Description: "a dict",
	})
	// Empty Type = list all types
	result, err := ListByType(db, ListQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total < 2 {
		t.Errorf("total = %d, want >= 2", result.Total)
	}
	types := map[string]bool{}
	for _, item := range result.Items {
		types[item.Type] = true
	}
	if !types["skill"] || !types["dict"] {
		t.Errorf("expected both skill and dict types, got %v", types)
	}
}

func TestSearch_ReturnsTotal(t *testing.T) {
	db := setupTestDB(t)
	for _, name := range []string{"sql-injection-basic", "sql-injection-advanced", "sql-injection-blind"} {
		InsertResource(db, Resource{
			Type: "skill", Name: name, Source: "builtin",
			Category: "exploit", Description: "SQL injection technique " + name,
			Body: "SQL injection attack",
		})
	}
	results, total, err := Search(db, SearchQuery{Query: "SQL injection", Type: "skill", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if len(results) != 2 {
		t.Errorf("results = %d, want 2", len(results))
	}
}

func insertVuln(t *testing.T, db *sql.DB, name, category, severity, product string) {
	t.Helper()
	metadata := fmt.Sprintf(`{"severity":"%s","product":"%s","vendor":"TestVendor"}`, severity, product)
	_, err := db.Exec(`INSERT OR REPLACE INTO resources
		(type,name,source,file_path,category,tags,description,body,metadata)
		VALUES ('vuln',?,'builtin','test.md',?,'rce',?,?,?)`,
		name, category,
		fmt.Sprintf("vuln %s %s", name, product),
		fmt.Sprintf("vuln body %s", name),
		metadata)
	if err != nil {
		t.Fatalf("insertVuln %s: %v", name, err)
	}
}

func TestSearch_ExcludesVulnByDefault(t *testing.T) {
	db := setupTestDB(t)
	// Insert a skill and a vuln that both match "injection"
	InsertResource(db, Resource{
		Type: "skill", Name: "sql-injection", Source: "builtin",
		Category: "exploit", Description: "SQL Injection techniques",
		Body: "SQL injection attack details",
	})
	insertVuln(t, db, "CVE-2021-44228", "rce", "CRITICAL", "Apache Log4j")

	// Search without specifying type — vuln should be excluded
	results, _, err := Search(db, SearchQuery{Query: "vuln", Limit: 10})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	for _, r := range results {
		if r.Type == "vuln" {
			t.Errorf("expected no vuln results in default search, got %q", r.Name)
		}
	}
}

func TestSearch_IncludesVulnWithExplicitType(t *testing.T) {
	db := setupTestDB(t)
	insertVuln(t, db, "CVE-2021-44228", "rce", "CRITICAL", "Apache Log4j")

	results, total, err := Search(db, SearchQuery{Query: "vuln", Type: "vuln", Limit: 10})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if total == 0 {
		t.Fatal("expected vuln results with explicit type, got 0")
	}
	if results[0].Type != "vuln" {
		t.Errorf("expected type vuln, got %q", results[0].Type)
	}
}

func TestSearch_SeverityFilter(t *testing.T) {
	db := setupTestDB(t)
	insertVuln(t, db, "CVE-2021-44228", "rce", "CRITICAL", "Apache Log4j")
	insertVuln(t, db, "CVE-2023-0001", "rce", "LOW", "SomeProduct")

	results, total, err := Search(db, SearchQuery{
		Query:    "vuln",
		Type:     "vuln",
		Severity: "CRITICAL",
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].Name != "CVE-2021-44228" {
		t.Errorf("expected CVE-2021-44228, got %q", results[0].Name)
	}
}

func TestSearch_ProductFilter(t *testing.T) {
	db := setupTestDB(t)
	insertVuln(t, db, "CVE-2021-44228", "rce", "CRITICAL", "Apache Log4j")
	insertVuln(t, db, "CVE-2023-0002", "rce", "HIGH", "OpenSSL")

	results, total, err := Search(db, SearchQuery{
		Query:   "vuln",
		Type:    "vuln",
		Product: "OpenSSL",
		Limit:   10,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].Name != "CVE-2023-0002" {
		t.Errorf("expected CVE-2023-0002, got %q", results[0].Name)
	}
}

func TestListByType_ExcludesVulnByDefault(t *testing.T) {
	db := setupTestDB(t)
	InsertResource(db, Resource{
		Type: "skill", Name: "test-skill", Source: "builtin",
		Category: "exploit", Description: "a skill",
	})
	insertVuln(t, db, "CVE-2021-44228", "rce", "CRITICAL", "Apache Log4j")

	// List without type — vuln should be excluded
	result, err := ListByType(db, ListQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range result.Items {
		if item.Type == "vuln" {
			t.Errorf("expected no vuln in default list, got %q", item.Name)
		}
	}
	if result.Total != 1 {
		t.Errorf("total = %d, want 1 (only skill)", result.Total)
	}
}

func TestListByType_VulnWithSeverityFilter(t *testing.T) {
	db := setupTestDB(t)
	insertVuln(t, db, "CVE-2021-44228", "rce", "CRITICAL", "Apache Log4j")
	insertVuln(t, db, "CVE-2023-0001", "rce", "LOW", "SomeProduct")

	result, err := ListByType(db, ListQuery{
		Type:     "vuln",
		Severity: "CRITICAL",
		Limit:    50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 {
		t.Errorf("total = %d, want 1", result.Total)
	}
	if len(result.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(result.Items))
	}
	if result.Items[0].Name != "CVE-2021-44228" {
		t.Errorf("expected CVE-2021-44228, got %q", result.Items[0].Name)
	}
}
