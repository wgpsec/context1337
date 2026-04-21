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

func TestSearchToolsAdapter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()

	result, err := svc.searchToolsAdapter(ctx, SearchToolsInput{Query: "nmap"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) == 0 {
		t.Fatal("expected at least one result")
	}
	for _, item := range result.Items {
		if item.Type != "tool" {
			t.Errorf("item %q has type %q, want tool", item.Name, item.Type)
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

func TestListToolsAdapter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()

	result, err := svc.listToolsAdapter(ctx, ListToolsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 {
		t.Errorf("total = %d, want 1", result.Total)
	}
	for _, item := range result.Items {
		if item.Type != "tool" {
			t.Errorf("item %q has type %q, want tool", item.Name, item.Type)
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

func TestGetToolAdapter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()

	// Create on-disk YAML file for the tool
	toolDir := filepath.Join(svc.DataDir, "Tools")
	if err := os.MkdirAll(toolDir, 0o755); err != nil {
		t.Fatal(err)
	}
	toolPath := filepath.Join(toolDir, "nmap.yaml")
	if err := os.WriteFile(toolPath, []byte("id: nmap\nbinary: nmap\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc.DB.Exec("UPDATE resources SET file_path=? WHERE name='nmap'", toolPath)

	result, err := svc.getToolAdapter(ctx, GetToolInput{Name: "nmap"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Type != "tool" {
		t.Errorf("type = %q, want tool", result.Type)
	}
	if result.Config == "" {
		t.Error("expected non-empty config")
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
