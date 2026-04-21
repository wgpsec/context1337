package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestGetFile_Dict(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	dictDir := filepath.Join(svc.DataDir, "Dic", "Auth", "password")
	os.MkdirAll(dictDir, 0o755)
	os.WriteFile(filepath.Join(dictDir, "Top100.txt"), []byte("pass1\npass2\npass3\npass4\npass5\n"), 0o644)

	result, err := svc.GetFile(ctx, GetFileInput{Path: "Auth/password/Top100.txt", Type: "dict", Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalLines != 5 {
		t.Errorf("total = %d, want 5", result.TotalLines)
	}
	if result.ReturnedLines != 3 {
		t.Errorf("returned = %d, want 3", result.ReturnedLines)
	}
	if result.Type != "dict" {
		t.Errorf("type = %q, want dict", result.Type)
	}
}

func TestGetFile_Payload(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	dir := filepath.Join(svc.DataDir, "Payload", "XSS")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "events.txt"), []byte("<img onerror>\n<svg onload>\n"), 0o644)

	result, err := svc.GetFile(ctx, GetFileInput{Path: "XSS/events.txt", Type: "payload"})
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalLines != 2 {
		t.Errorf("total = %d, want 2", result.TotalLines)
	}
}

func TestGetFile_InvalidType(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	_, err := svc.GetFile(ctx, GetFileInput{Path: "test.txt", Type: "skill"})
	if err == nil {
		t.Fatal("expected error for skill type")
	}
}

func TestGetFile_PathTraversal(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	_, err := svc.GetFile(ctx, GetFileInput{Path: "../../etc/passwd", Type: "dict"})
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
}
