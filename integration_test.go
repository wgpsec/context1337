//go:build integration

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Esonhugh/context1337/internal/api"
	"github.com/Esonhugh/context1337/internal/search"
	"github.com/Esonhugh/context1337/internal/storage"
)

func TestIntegration_FullStack(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "runtime", "runtime.db")

	db, err := storage.OpenDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Seed test data
	search.InsertResource(db, search.Resource{
		Type: "skill", Name: "sql-injection", Source: "builtin",
		FilePath: "skills/sql-injection/SKILL.md", Category: "exploit",
		Tags: "sqli,owasp,web", Difficulty: "medium",
		Description: "SQL Injection attack techniques",
		Body:        "SQL注入攻击是一种常见的Web安全漏洞",
	})
	search.InsertResource(db, search.Resource{
		Type: "dict", Name: "Auth/password/Top10.txt", Source: "builtin",
		FilePath: "Dic/Auth/password/Top10.txt", Category: "Auth",
		Description: "Top 10 passwords",
	})

	// Build router with nil mcpHandler
	handler := api.NewRouter(db, dir, "test-key", nil)
	server := httptest.NewServer(handler)
	defer server.Close()

	// Test: health endpoint with auth
	req, _ := http.NewRequest("GET", server.URL+"/api/health", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("health: status %d", resp.StatusCode)
	}

	var health map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&health)
	resp.Body.Close()
	if health["status"] != "ok" {
		t.Errorf("health status = %v", health["status"])
	}

	// Test: unauthorized request
	req2, _ := http.NewRequest("GET", server.URL+"/api/stats", nil)
	resp2, _ := http.DefaultClient.Do(req2)
	if resp2.StatusCode != 401 {
		t.Errorf("expected 401 without auth, got %d", resp2.StatusCode)
	}
	resp2.Body.Close()

	// Test: stats endpoint with auth
	req3, _ := http.NewRequest("GET", server.URL+"/api/stats", nil)
	req3.Header.Set("Authorization", "Bearer test-key")
	resp3, _ := http.DefaultClient.Do(req3)
	if resp3.StatusCode != 200 {
		t.Errorf("stats: status %d", resp3.StatusCode)
	}
	resp3.Body.Close()

	t.Log("Integration test passed: health, auth, stats all working")
}
