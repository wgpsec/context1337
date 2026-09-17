package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/wgpsec/context1337/internal/auth"
	"github.com/wgpsec/context1337/internal/search"
)

func TestSearchOmitsUnauthorizedSources(t *testing.T) {
	svc := setupUnifiedTest(t)
	if err := search.InsertResource(svc.DB, search.Resource{
		Type: "vuln", Name: "TEAM-ONLY", Source: "team",
		Description: "private seeyon marker", Body: "private seeyon marker",
	}); err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithPrincipal(context.Background(), auth.NewPrincipal("pub", auth.AccessRead, []string{auth.SourceBuiltin}))
	result, err := svc.Search(ctx, SearchInput{Query: "seeyon", Type: "vuln", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range result.Items {
		if item.Source == "team" {
			t.Fatalf("restricted search leaked team: %+v", item)
		}
	}
}

func TestGetUnauthorizedSourceIsNotFound(t *testing.T) {
	svc := setupUnifiedTest(t)
	if err := search.InsertResource(svc.DB, search.Resource{
		Type: "vuln", Name: "TEAM-ONLY", Source: "team",
		Description: "private team vuln", Body: "private team vuln",
	}); err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithPrincipal(context.Background(), auth.NewPrincipal("pub", auth.AccessRead, []string{auth.SourceBuiltin}))
	_, err := svc.Get(ctx, GetInput{ID: "absec://team/vuln/TEAM-ONLY"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want not found", err)
	}
}

func TestGetFileUnauthorizedSourceIsNotFound(t *testing.T) {
	svc := setupUnifiedTest(t)
	if _, err := svc.DB.Exec(`INSERT INTO resources (type,name,source,file_path,description,body)
		VALUES ('dict','Auth/password/Top100.txt','team','','Team password list','Team password list')`); err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithPrincipal(context.Background(), auth.NewPrincipal("pub", auth.AccessRead, []string{auth.SourceBuiltin}))
	_, err := svc.GetFile(ctx, GetFileInput{ID: "absec://team/dict/Auth%2Fpassword%2FTop100.txt"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want not found", err)
	}
}
