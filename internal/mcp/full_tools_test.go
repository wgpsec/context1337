package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Search adapter tests
// ---------------------------------------------------------------------------

func TestSearchSkillAdapter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()

	result, err := svc.searchSkillAdapter(ctx, SearchSkillInput{Query: "SQL injection"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) == 0 {
		t.Fatal("expected at least one result")
	}
	for _, item := range result.Items {
		if item.Type != "skill" {
			t.Errorf("item %q has type %q, want skill", item.Name, item.Type)
		}
	}
}

func TestSearchDictsAdapter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()

	result, err := svc.searchDictsAdapter(ctx, SearchDictsInput{Query: "password"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) == 0 {
		t.Fatal("expected at least one result")
	}
	for _, item := range result.Items {
		if item.Type != "dict" {
			t.Errorf("item %q has type %q, want dict", item.Name, item.Type)
		}
	}
}

func TestSearchPayloadAdapter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()

	result, err := svc.searchPayloadAdapter(ctx, SearchPayloadInput{Query: "XSS"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) == 0 {
		t.Fatal("expected at least one result")
	}
	for _, item := range result.Items {
		if item.Type != "payload" {
			t.Errorf("item %q has type %q, want payload", item.Name, item.Type)
		}
	}
}

// ---------------------------------------------------------------------------
// List adapter tests
// ---------------------------------------------------------------------------

func TestListSkillsAdapter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()

	result, err := svc.listSkillsAdapter(ctx, ListSkillsInput{})
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

func TestListDictsAdapter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()

	result, err := svc.listDictsAdapter(ctx, ListDictsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 {
		t.Errorf("total = %d, want 1", result.Total)
	}
	for _, item := range result.Items {
		if item.Type != "dict" {
			t.Errorf("item %q has type %q, want dict", item.Name, item.Type)
		}
	}
}

func TestListPayloadsAdapter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()

	result, err := svc.listPayloadsAdapter(ctx, ListPayloadsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 {
		t.Errorf("total = %d, want 1", result.Total)
	}
	for _, item := range result.Items {
		if item.Type != "payload" {
			t.Errorf("item %q has type %q, want payload", item.Name, item.Type)
		}
	}
}

// ---------------------------------------------------------------------------
// Get adapter tests
// ---------------------------------------------------------------------------

func TestGetSkillAdapter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()

	result, err := svc.getSkillAdapter(ctx, GetSkillInput{Name: "sql-injection"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Type != "skill" {
		t.Errorf("type = %q, want skill", result.Type)
	}
	if result.Name != "sql-injection" {
		t.Errorf("name = %q, want sql-injection", result.Name)
	}
	if result.Body == "" {
		t.Error("expected non-empty body at default (summary) depth")
	}
}

func TestGetSkillAdapter_DepthFull(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()

	// Create on-disk SKILL.md so depth=full can read from filesystem
	skillDir := filepath.Join(svc.DataDir, "skills", "exploit", "sql-injection")
	os.MkdirAll(skillDir, 0o755)
	os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: sql-injection\n---\nbody content"), 0o644)
	svc.DB.Exec("UPDATE resources SET file_path=? WHERE name='sql-injection'",
		filepath.Join(skillDir, "SKILL.md"))

	result, err := svc.getSkillAdapter(ctx, GetSkillInput{Name: "sql-injection", Depth: "full"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Type != "skill" {
		t.Errorf("type = %q, want skill", result.Type)
	}
	if result.Body == "" {
		t.Error("expected non-empty body at full depth")
	}
}

func TestGetDictAdapter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()

	// Create on-disk dictionary file
	dictDir := filepath.Join(svc.DataDir, "Dic", "Auth", "password")
	if err := os.MkdirAll(dictDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dictPath := filepath.Join(dictDir, "Top100.txt")
	if err := os.WriteFile(dictPath, []byte("pass1\npass2\npass3\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := svc.getDictAdapter(ctx, GetDictInput{Path: "Auth/password/Top100.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Type != "dict" {
		t.Errorf("type = %q, want dict", result.Type)
	}
	if result.TotalLines != 3 {
		t.Errorf("total_lines = %d, want 3", result.TotalLines)
	}
}

func TestGetPayloadAdapter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()

	// Create on-disk payload file
	payloadDir := filepath.Join(svc.DataDir, "Payload", "XSS")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(payloadDir, "events.txt")
	if err := os.WriteFile(payloadPath, []byte("<img onerror>\n<svg onload>\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := svc.getPayloadAdapter(ctx, GetPayloadInput{Path: "XSS/events.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Type != "payload" {
		t.Errorf("type = %q, want payload", result.Type)
	}
	if result.TotalLines != 2 {
		t.Errorf("total_lines = %d, want 2", result.TotalLines)
	}
}

// ---------------------------------------------------------------------------
// Vuln adapter tests
// ---------------------------------------------------------------------------

func TestSearchVulnAdapter(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.searchVulnAdapter(context.Background(), SearchVulnInput{
		Query: "JNDI",
	})
	if err != nil {
		t.Fatalf("searchVulnAdapter: %v", err)
	}
	if res.Total == 0 {
		t.Fatal("expected vuln results")
	}
	for _, item := range res.Items {
		if item.Type != "vuln" {
			t.Errorf("type = %q, want vuln", item.Type)
		}
	}
}

func TestSearchVulnAdapter_SeverityFilter(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.searchVulnAdapter(context.Background(), SearchVulnInput{
		Severity: "CRITICAL",
	})
	if err != nil {
		t.Fatalf("searchVulnAdapter: %v", err)
	}
	if res.Total != 1 {
		t.Errorf("total = %d, want 1", res.Total)
	}
}

func TestListVulnsAdapter(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.listVulnsAdapter(context.Background(), ListVulnsInput{})
	if err != nil {
		t.Fatalf("listVulnsAdapter: %v", err)
	}
	if res.Total != 1 {
		t.Errorf("total = %d, want 1", res.Total)
	}
	for _, item := range res.Items {
		if item.Type != "vuln" {
			t.Errorf("type = %q, want vuln", item.Type)
		}
	}
}

func TestGetVulnAdapter_Brief(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.getVulnAdapter(context.Background(), GetVulnInput{
		Name: "CVE-2021-44228",
	})
	if err != nil {
		t.Fatalf("getVulnAdapter: %v", err)
	}
	if res.Severity != "CRITICAL" {
		t.Errorf("Severity = %q", res.Severity)
	}
	if res.Body != "" {
		t.Error("brief mode should not include body")
	}
}

func TestGetVulnAdapter_Full(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.getVulnAdapter(context.Background(), GetVulnInput{
		Name:  "CVE-2021-44228",
		Depth: "full",
	})
	if err != nil {
		t.Fatalf("getVulnAdapter full: %v", err)
	}
	if res.Body == "" {
		t.Error("full mode should include body")
	}
	if res.Fingerprint != "header=X-Log4j" {
		t.Errorf("Fingerprint = %q", res.Fingerprint)
	}
}
