package search

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func TestRuntimeCorpusCanonicalSkillGoldenRanking(t *testing.T) {
	dbPath := filepath.Join("..", "..", "data", "runtime", "runtime.db")
	if _, err := os.Stat(dbPath); err != nil {
		t.Skipf("runtime corpus is not available: %v", err)
	}

	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro", dbPath))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	tests := []struct {
		query   string
		wantTop string
	}{
		{"JWT algorithm confusion", "jwt-attack-methodology"},
		{"JWT none algorithm bypass", "jwt-attack-methodology"},
		{"JWT authentication bypass", "jwt-attack-methodology"},
		{"JWT 算法混淆", "jwt-attack-methodology"},
		{"SQL injection", "sql-injection-methodology"},
		{"file upload webshell", "file-upload-methodology"},
		{"OAuth redirect URI", "oauth-sso-attack"},
		{"Java deserialization", "java-deserialization-methodology"},
	}

	for _, test := range tests {
		t.Run(test.query, func(t *testing.T) {
			results, _, err := Search(db, SearchQuery{
				Query: test.query,
				Type:  "skill",
				Limit: 150,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(results) == 0 || results[0].Name != test.wantTop {
				t.Fatalf("top results = %v, want %s", resultNames(results), test.wantTop)
			}
		})
	}
}

func TestRuntimeCorpusCanonicalSearchP95(t *testing.T) {
	dbPath := filepath.Join("..", "..", "data", "runtime", "runtime.db")
	if _, err := os.Stat(dbPath); err != nil {
		t.Skipf("runtime corpus is not available: %v", err)
	}

	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro", dbPath))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	queries := []string{
		"JWT algorithm confusion",
		"JWT none algorithm bypass",
		"SQL injection",
		"file upload webshell",
		"OAuth redirect URI",
		"Java deserialization",
	}
	for _, query := range queries {
		if _, _, err := Search(db, SearchQuery{Query: query, Type: "skill", Limit: 150}); err != nil {
			t.Fatal(err)
		}
	}

	durations := make([]time.Duration, 0, 120)
	for i := 0; i < 120; i++ {
		query := queries[i%len(queries)]
		started := time.Now()
		if _, _, err := Search(db, SearchQuery{Query: query, Type: "skill", Limit: 150}); err != nil {
			t.Fatal(err)
		}
		durations = append(durations, time.Since(started))
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p95 := durations[(len(durations)*95+99)/100-1]
	t.Logf("canonical search p95=%s", p95)
	if p95 > 20*time.Millisecond {
		t.Fatalf("canonical search p95 = %s, want <= 20ms", p95)
	}
}
