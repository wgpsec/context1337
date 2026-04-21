package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Esonhugh/context1337/internal/search"
)

func TestListPayloads(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	search.InsertResource(svc.DB, search.Resource{
		Type: "payload", Name: "XSS/events.txt", Source: "builtin",
		Category: "xss", Description: "XSS event handlers",
	})
	search.InsertResource(svc.DB, search.Resource{
		Type: "payload", Name: "SQLi/columns.txt", Source: "builtin",
		Category: "sqli", Description: "SQL column names",
	})

	result, err := svc.ListPayloads(ctx, ListPayloadsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 2 {
		t.Errorf("total = %d, want 2", result.Total)
	}

	// Filter by category
	result2, err := svc.ListPayloads(ctx, ListPayloadsInput{Category: "xss"})
	if err != nil {
		t.Fatal(err)
	}
	if result2.Total != 1 {
		t.Errorf("filtered total = %d, want 1", result2.Total)
	}
}

func TestSearchPayload(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	search.InsertResource(svc.DB, search.Resource{
		Type: "payload", Name: "XSS/events.txt", Source: "builtin",
		Category: "xss", Description: "XSS event handler payloads",
		Body: "onerror onfocus onload",
	})

	result, err := svc.SearchPayload(ctx, SearchPayloadInput{Query: "XSS event"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) == 0 {
		t.Fatal("expected results")
	}
}

func TestGetPayload(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	dir := filepath.Join(svc.DataDir, "Payload", "XSS")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "events.txt"), []byte("<img onerror>\n<svg onload>\n"), 0o644)

	result, err := svc.GetPayload(ctx, GetPayloadInput{Path: "XSS/events.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalLines != 2 {
		t.Errorf("total_lines = %d, want 2", result.TotalLines)
	}
}
