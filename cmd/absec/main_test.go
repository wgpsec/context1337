package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/wgpsec/context1337/internal/buildinfo"
	"github.com/wgpsec/context1337/internal/search"
	"github.com/wgpsec/context1337/internal/storage"
)

func TestRootCommandReportsReleaseVersion(t *testing.T) {
	command := newRootCmd()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"--version"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if want := "absec version " + buildinfo.Version + "\n"; output.String() != want {
		t.Fatalf("version output = %q, want %q", output.String(), want)
	}
}

// The MCP transport holds streaming responses open, so exemptStreamingWrites
// must clear the write deadline for exactly those requests. If this regresses,
// every SSE stream dies once the server WriteTimeout elapses.
func TestIsStreamingRequestMatchesOnlyEventStreamGets(t *testing.T) {
	cases := []struct {
		name   string
		method string
		accept string
		want   bool
	}{
		{"sse GET is exempted", http.MethodGet, "text/event-stream", true},
		{"sse GET with json listed first is exempted", http.MethodGet, "application/json, text/event-stream", true},
		{"plain GET is not exempted", http.MethodGet, "application/json", false},
		{"sse POST is not exempted", http.MethodPost, "application/json, text/event-stream", false},
		{"missing accept is not exempted", http.MethodGet, "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/mcp", nil)
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}
			if got := isStreamingRequest(req); got != tc.want {
				t.Fatalf("isStreamingRequest = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestExemptStreamingWritesCallsWrappedHandler(t *testing.T) {
	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true })
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Accept", "text/event-stream")
	exemptStreamingWrites(inner).ServeHTTP(httptest.NewRecorder(), req)
	if !reached {
		t.Fatal("wrapped handler was not called")
	}
}

func TestFinalizeIndexCommandBuildsTheShippedFTSContract(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "builtin.db")
	db, err := storage.OpenDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		INSERT INTO resources
			(type, name, source, file_path, category, tags, description, body, metadata)
		VALUES
			('vuln', 'CVE-2023-1454', 'builtin', 'Vuln/CVE-2023-1454.md',
			 'middleware', 'sqli', 'JeecgBoot 积木报表 SQL 注入漏洞', '', '{}')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	command := newRootCmd()
	command.SetArgs([]string{"finalize-index", "--db", dbPath})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}

	db, err = storage.OpenDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	contract, err := storage.GetMeta(db, "fts_contract_version")
	if err != nil {
		t.Fatal(err)
	}
	if contract != "go-security-tokenizer-v3" {
		t.Fatalf("fts_contract_version = %q, want go-security-tokenizer-v3", contract)
	}
	results, _, err := search.Search(db, search.SearchQuery{
		Query: "积木报表",
		Type:  "vuln",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Name != "CVE-2023-1454" {
		t.Fatalf("finalized index results = %v, want CVE-2023-1454", results)
	}
}
