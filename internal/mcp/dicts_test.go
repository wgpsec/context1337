package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Esonhugh/context1337/internal/search"
)

func TestListDicts(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	search.InsertResource(svc.DB, search.Resource{
		Type: "dict", Name: "Auth/password/Top10.txt", Source: "builtin",
		FilePath: "Dic/Auth/password/Top10.txt", Category: "Auth",
		Description: "Top 10 passwords",
	})
	results, err := svc.ListDicts(ctx, ListDictsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least 1 dict")
	}
}

func TestListDicts_TypeFilter(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	search.InsertResource(svc.DB, search.Resource{
		Type: "dict", Name: "Auth/Top10.txt", Source: "builtin",
		FilePath: "Dic/Auth/Top10.txt", Category: "Auth",
	})
	search.InsertResource(svc.DB, search.Resource{
		Type: "dict", Name: "Network/ports.txt", Source: "builtin",
		FilePath: "Dic/Network/ports.txt", Category: "Network",
	})
	results, err := svc.ListDicts(ctx, ListDictsInput{Type: "Auth"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 Auth dict, got %d", len(results))
	}
}

func TestGetDict(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	dictDir := filepath.Join(svc.DataDir, "Dic", "Auth", "password")
	os.MkdirAll(dictDir, 0o755)
	os.WriteFile(filepath.Join(dictDir, "Top10.txt"), []byte("pass1\npass2\npass3\npass4\npass5\n"), 0o644)

	result, err := svc.GetDict(ctx, GetDictInput{Path: "Auth/password/Top10.txt", Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalLines != 5 {
		t.Errorf("total = %d, want 5", result.TotalLines)
	}
	if result.ReturnedLines != 3 {
		t.Errorf("returned = %d, want 3", result.ReturnedLines)
	}
}
