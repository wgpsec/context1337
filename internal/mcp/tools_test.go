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
		Category: "scan", Description: "Port scanner",
		Metadata: `{"binary":"nmap","homepage":"https://nmap.org"}`,
	})
	result, err := svc.ListTools(ctx, ListToolsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) == 0 {
		t.Fatal("expected at least 1 tool")
	}
	if result.Items[0].Name != "nmap" {
		t.Errorf("name = %q, want nmap", result.Items[0].Name)
	}
	if result.Items[0].Category != "scan" {
		t.Errorf("category = %q, want scan", result.Items[0].Category)
	}
	if result.Items[0].Homepage != "https://nmap.org" {
		t.Errorf("homepage = %q, want https://nmap.org", result.Items[0].Homepage)
	}
}

func TestGetTool(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	toolDir := filepath.Join(svc.DataDir, "Tools")
	os.MkdirAll(toolDir, 0o755)
	toolPath := filepath.Join(toolDir, "nmap.yaml")
	os.WriteFile(toolPath, []byte("id: nmap\nbinary: nmap\n"), 0o644)

	search.InsertResource(svc.DB, search.Resource{
		Type: "tool", Name: "nmap", Source: "builtin",
		Category: "scan", Description: "Port scanner",
		FilePath: toolPath,
		Metadata: `{"binary":"nmap","homepage":"https://nmap.org"}`,
	})
	result, err := svc.GetTool(ctx, GetToolInput{Name: "nmap"})
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

func TestGetTool_NotFound(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	_, err := svc.GetTool(ctx, GetToolInput{Name: "nonexistent"})
	if err == nil {
		t.Fatal("expected error")
	}
}
