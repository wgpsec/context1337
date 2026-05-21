package mcp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

func TestGetFile_WithStableID_DictRoundTrip(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	dictDir := filepath.Join(svc.DataDir, "Dic", "Auth", "password")
	if err := os.MkdirAll(dictDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dictPath := filepath.Join(dictDir, "Top100.txt")
	if err := os.WriteFile(dictPath, []byte("pass1\npass2\npass3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	searchResult, err := svc.Search(ctx, SearchInput{Type: "dict", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(searchResult.Items) == 0 {
		t.Fatal("expected dict search result")
	}
	got, err := svc.GetFile(ctx, GetFileInput{ID: searchResult.Items[0].ID, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != searchResult.Items[0].ID {
		t.Fatalf("ID = %q, want %q", got.ID, searchResult.Items[0].ID)
	}
	if got.Type != "dict" || got.Path != "Auth/password/Top100.txt" {
		t.Fatalf("got (%q, %q), want (dict, Auth/password/Top100.txt)", got.Type, got.Path)
	}
	if got.ReturnedLines != 2 {
		t.Fatalf("ReturnedLines = %d, want 2", got.ReturnedLines)
	}
}

func TestGetFile_WithStableID_PayloadRoundTrip(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	payloadDir := filepath.Join(svc.DataDir, "Payload", "XSS")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(payloadDir, "events.txt")
	if err := os.WriteFile(payloadPath, []byte("<img onerror>\n<svg onload>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetFile(ctx, GetFileInput{ID: "absec://builtin/payload/XSS%2Fevents.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "absec://builtin/payload/XSS%2Fevents.txt" {
		t.Fatalf("ID = %q", got.ID)
	}
	if got.TotalLines != 2 {
		t.Fatalf("TotalLines = %d, want 2", got.TotalLines)
	}
}

func TestGetFile_WithStableID_FallsBackToDataDirWhenFilePathEmpty(t *testing.T) {
	svc := setupUnifiedTest(t)
	dictDir := filepath.Join(svc.DataDir, "Dic", "Auth", "password")
	if err := os.MkdirAll(dictDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dictDir, "Top100.txt"), []byte("fallback1\nfallback2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DB.Exec("UPDATE resources SET file_path='' WHERE type='dict' AND source='builtin' AND name='Auth/password/Top100.txt'"); err != nil {
		t.Fatal(err)
	}

	got, err := svc.GetFile(context.Background(), GetFileInput{ID: "absec://builtin/dict/Auth%2Fpassword%2FTop100.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if got.TotalLines != 2 {
		t.Fatalf("TotalLines = %d, want 2", got.TotalLines)
	}
}

func TestGetFile_WithStableID_RejectsTraversalName(t *testing.T) {
	svc := setupUnifiedTest(t)
	if _, err := svc.DB.Exec(`INSERT INTO resources (type,name,source,file_path,description,body)
		VALUES ('dict','../secret.txt','builtin','','Traversal test','Traversal test')`); err != nil {
		t.Fatal(err)
	}

	_, err := svc.GetFile(context.Background(), GetFileInput{ID: "absec://builtin/dict/..%2Fsecret.txt"})
	if err == nil {
		t.Fatal("expected traversal error")
	}
	if !strings.Contains(err.Error(), "invalid path") {
		t.Fatalf("error = %q, want invalid path", err.Error())
	}
}

func TestGetFile_WithStableID_RejectsLegacyPathMismatch(t *testing.T) {
	svc := setupUnifiedTest(t)
	_, err := svc.GetFile(context.Background(), GetFileInput{ID: "absec://builtin/dict/Auth%2Fpassword%2FTop100.txt", Type: "dict", Path: "Other/passwords.txt"})
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("error = %q, want conflict", err.Error())
	}
}

func TestGetFile_WithStableID_RejectsLegacyTypeMismatch(t *testing.T) {
	svc := setupUnifiedTest(t)
	_, err := svc.GetFile(context.Background(), GetFileInput{ID: "absec://builtin/dict/Auth%2Fpassword%2FTop100.txt", Type: "payload"})
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("error = %q, want conflict", err.Error())
	}
}

func TestGetFile_WithStableID_TeamDictReadsFromTeamDir(t *testing.T) {
	svc := setupUnifiedTest(t)
	teamDir := filepath.Join(svc.DataDir, "team", "Dic", "Auth", "password")
	if err := os.MkdirAll(teamDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teamDir, "Top100.txt"), []byte("team-pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	builtinDir := filepath.Join(svc.DataDir, "Dic", "Auth", "password")
	if err := os.MkdirAll(builtinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(builtinDir, "Top100.txt"), []byte("builtin-pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DB.Exec(`INSERT INTO resources (type,name,source,file_path,description,body)
		VALUES ('dict','Auth/password/Top100.txt','team','','Team password list','Team password list')`); err != nil {
		t.Fatal(err)
	}

	got, err := svc.GetFile(context.Background(), GetFileInput{ID: "absec://team/dict/Auth%2Fpassword%2FTop100.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Content != "team-pass" {
		t.Fatalf("Content = %q, want team content", got.Content)
	}
}

func TestGetFile_WithStableID_SameNameCollisionUsesIDSource(t *testing.T) {
	svc := setupUnifiedTest(t)
	builtinDir := filepath.Join(svc.DataDir, "Dic", "Shared")
	if err := os.MkdirAll(builtinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(builtinDir, "words.txt"), []byte("builtin-word\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	teamDir := filepath.Join(svc.DataDir, "team", "Dic", "Shared")
	if err := os.MkdirAll(teamDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(teamDir, "words.txt"), []byte("team-word\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DB.Exec(`INSERT INTO resources (type,name,source,file_path,description,body)
		VALUES ('dict','Shared/words.txt','builtin','','Builtin shared words','Builtin shared words'),
		       ('dict','Shared/words.txt','team','','Team shared words','Team shared words')`); err != nil {
		t.Fatal(err)
	}

	builtin, err := svc.GetFile(context.Background(), GetFileInput{ID: "absec://builtin/dict/Shared%2Fwords.txt"})
	if err != nil {
		t.Fatal(err)
	}
	team, err := svc.GetFile(context.Background(), GetFileInput{ID: "absec://team/dict/Shared%2Fwords.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if builtin.Content != "builtin-word" {
		t.Fatalf("builtin Content = %q, want builtin content", builtin.Content)
	}
	if team.Content != "team-word" {
		t.Fatalf("team Content = %q, want team content", team.Content)
	}
}

func TestGetFile_WithStableID_RejectsUnsupportedFileSource(t *testing.T) {
	svc := setupUnifiedTest(t)
	if _, err := svc.DB.Exec(`INSERT INTO resources (type,name,source,file_path,description,body)
		VALUES ('dict','External/words.txt','external','','External words','External words')`); err != nil {
		t.Fatal(err)
	}

	_, err := svc.GetFile(context.Background(), GetFileInput{ID: "absec://external/dict/External%2Fwords.txt"})
	if err == nil {
		t.Fatal("expected unsupported source error")
	}
	if !strings.Contains(err.Error(), "unsupported file source") || !strings.Contains(err.Error(), "external") {
		t.Fatalf("error = %q, want unsupported external source", err.Error())
	}
}

func TestGetFile_WithStableID_RejectsWrongType(t *testing.T) {
	svc := setupUnifiedTest(t)
	_, err := svc.GetFile(context.Background(), GetFileInput{ID: "absec://builtin/skill/sql-injection"})
	if err == nil {
		t.Fatal("expected wrong type error")
	}
	if !strings.Contains(err.Error(), "type=skill") {
		t.Fatalf("error = %q, want type=skill", err.Error())
	}
}
