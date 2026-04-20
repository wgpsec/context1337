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
		Type: "tool", Name: "nmap", Source: "builtin",
		FilePath: "Tools/nmap.yaml", Category: "scan",
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
	if results[0].Name != "nmap" {
		t.Errorf("name = %q, want nmap", results[0].Name)
	}
}

func TestGetTool(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	toolDir := filepath.Join(svc.DataDir, "Tools")
	os.MkdirAll(toolDir, 0o755)
	toolPath := filepath.Join(toolDir, "nmap.yaml")
	os.WriteFile(toolPath, []byte("id: nmap\nname: Nmap\ndescription: Network scanner\ncategory: scan\nbinary: nmap\ncommand_template: \"nmap {{.target}}\"\n"), 0o644)

	search.InsertResource(svc.DB, search.Resource{
		Type: "tool", Name: "nmap", Source: "builtin",
		FilePath: toolPath, Category: "scan",
		Description: "Network scanner",
	})
	result, err := svc.GetTool(ctx, GetToolInput{Name: "nmap"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "nmap" {
		t.Errorf("name = %q", result.Name)
	}
	if result.Config == "" {
		t.Error("config should not be empty")
	}
}

func TestGetTool_NotFound(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	_, err := svc.GetTool(ctx, GetToolInput{Name: "nonexistent"})
	if err == nil {
		t.Fatal("expected error")
	}
}
