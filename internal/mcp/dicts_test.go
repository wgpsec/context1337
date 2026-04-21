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
		Category: "auth", Description: "common passwords",
	})
	result, err := svc.ListDicts(ctx, ListDictsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total == 0 || len(result.Items) == 0 {
		t.Fatal("expected results")
	}
}

func TestListDicts_CategoryFilter(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	search.InsertResource(svc.DB, search.Resource{
		Type: "dict", Name: "Auth/user.txt", Source: "builtin", Category: "auth",
	})
	search.InsertResource(svc.DB, search.Resource{
		Type: "dict", Name: "Web/dir.txt", Source: "builtin", Category: "web",
	})
	result, err := svc.ListDicts(ctx, ListDictsInput{Category: "auth"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 {
		t.Errorf("total = %d, want 1", result.Total)
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
