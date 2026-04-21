package mcp

import (
	"context"
	"testing"

	"github.com/Esonhugh/context1337/internal/search"
)

func TestListDocs(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	search.InsertResource(svc.DB, search.Resource{
		Type: "doc", Name: "Cheatsheet", Source: "builtin",
		Description: "Pentest cheatsheet",
		Body:        "Quick reference for penetration testing",
	})
	search.InsertResource(svc.DB, search.Resource{
		Type: "doc", Name: "默认密码", Source: "builtin",
		Description: "Default passwords",
		Body:        "Common default credentials",
	})

	result, err := svc.ListDocs(ctx, ListDocsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 2 {
		t.Errorf("total = %d, want 2", result.Total)
	}
}

func TestSearchDoc(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	search.InsertResource(svc.DB, search.Resource{
		Type: "doc", Name: "Cheatsheet", Source: "builtin",
		Description: "Pentest cheatsheet reference",
		Body:        "penetration testing workflow reconnaissance scanning",
	})

	result, err := svc.SearchDoc(ctx, SearchDocInput{Query: "penetration testing"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) == 0 {
		t.Fatal("expected results")
	}
	if result.Items[0].Name != "Cheatsheet" {
		t.Errorf("name = %q, want Cheatsheet", result.Items[0].Name)
	}
}

func TestGetDoc(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	search.InsertResource(svc.DB, search.Resource{
		Type: "doc", Name: "Cheatsheet", Source: "builtin",
		Description: "Pentest cheatsheet",
		Body:        "# Cheatsheet\nFull content here",
	})

	result, err := svc.GetDoc(ctx, GetDocInput{Name: "Cheatsheet"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Body == "" {
		t.Error("expected body content")
	}
}

func TestGetDoc_NotFound(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	_, err := svc.GetDoc(ctx, GetDocInput{Name: "nonexistent"})
	if err == nil {
		t.Fatal("expected error")
	}
}
