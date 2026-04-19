package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Esonhugh/context1337/internal/search"
)

func TestSearchPayload(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	search.InsertResource(svc.DB, search.Resource{
		Type: "payload", Name: "XSS/events.txt", Source: "builtin",
		FilePath: "Payload/XSS/events.txt", Category: "xss",
		Description: "XSS event handler payloads",
		Body:        "onerror onload onfocus payloads for XSS",
	})
	results, err := svc.SearchPayload(ctx, SearchPayloadInput{Query: "XSS"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("expected results")
	}
}

func TestGetPayload(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()
	payDir := filepath.Join(svc.DataDir, "Payload", "XSS")
	os.MkdirAll(payDir, 0o755)
	os.WriteFile(filepath.Join(payDir, "events.txt"),
		[]byte("<img src=x onerror=alert(1)>\n<svg onload=alert(1)>\n"), 0o644)
	result, err := svc.GetPayload(ctx, GetPayloadInput{Path: "XSS/events.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalLines != 2 {
		t.Errorf("total = %d, want 2", result.TotalLines)
	}
}
