package main

import (
	"path/filepath"
	"testing"

	"github.com/wgpsec/context1337/internal/search"
	"github.com/wgpsec/context1337/internal/storage"
)

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
