package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Esonhugh/context1337/internal/search"
)

func TestListTools(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	search.InsertResource(svc.DB, search.Resource{
		Type: "tool", Name: "ext_nmap", Source: "builtin",
		FilePath: "Tools/ext_nmap.yaml", Category: "scan",
		Description: "Network scanner",
		Metadata:    `{"binary":"nmap"}`,
	})
	results, err := svc.ListTools(ctx, ListToolsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least 1 tool")
	}
	if results[0].ID != "ext_nmap" {
		t.Errorf("id = %q, want ext_nmap", results[0].ID)
	}
}

func TestGetTool(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	toolDir := filepath.Join(svc.DataDir, "Tools")
	os.MkdirAll(toolDir, 0o755)
	toolPath := filepath.Join(toolDir, "ext_nmap.yaml")
	os.WriteFile(toolPath, []byte("id: ext_nmap\nname: Nmap\ndescription: Network scanner\ncategory: scan\nbinary: nmap\ncommand_template: \"nmap {{.target}}\"\n"), 0o644)

	search.InsertResource(svc.DB, search.Resource{
		Type: "tool", Name: "ext_nmap", Source: "builtin",
		FilePath: toolPath, Category: "scan",
		Description: "Network scanner",
	})
	result, err := svc.GetTool(ctx, GetToolInput{ID: "ext_nmap"})
	if err != nil {
		t.Fatal(err)
	}
	if result.ID != "ext_nmap" {
		t.Errorf("id = %q", result.ID)
	}
	if result.Config == "" {
		t.Error("config should not be empty")
	}
}

func TestGetTool_NotFound(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	_, err := svc.GetTool(ctx, GetToolInput{ID: "nonexistent"})
	if err == nil {
		t.Fatal("expected error")
	}
}
