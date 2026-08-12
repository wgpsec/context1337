package storage_test

import (
	"path/filepath"
	"testing"

	"github.com/wgpsec/context1337/internal/search"
	"github.com/wgpsec/context1337/internal/storage"
)

func TestInitRuntimeMigratesLegacyFTSContract(t *testing.T) {
	dir := t.TempDir()
	builtinPath := filepath.Join(dir, "builtin.db")
	runtimePath := filepath.Join(dir, "runtime", "runtime.db")

	builtinDB, err := storage.OpenDB(builtinPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SetMeta(builtinDB, "builtin_version", "test-v1"); err != nil {
		t.Fatal(err)
	}
	if err := builtinDB.Close(); err != nil {
		t.Fatal(err)
	}

	runtimeDB, err := storage.OpenDB(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SetMeta(runtimeDB, "builtin_version", "test-v1"); err != nil {
		t.Fatal(err)
	}
	result, err := runtimeDB.Exec(`
		INSERT INTO resources
			(type, name, source, file_path, category, tags, description, body, metadata)
		VALUES
			('vuln', 'CVE-2023-1454', 'builtin', 'Vuln/CVE-2023-1454.md',
			 'middleware', 'sqli', 'JeecgBoot 积木报表 SQL 注入漏洞', '', '{}')`)
	if err != nil {
		t.Fatal(err)
	}
	resourceID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeDB.Exec(`
		INSERT INTO resources_fts(rowid, name, description, tags, category, body)
		VALUES (?, 'CVE-2023-1454', 'JeecgBoot 积木 报表 SQL 注入 漏洞', 'sqli', 'middleware', '')`,
		resourceID); err != nil {
		t.Fatal(err)
	}
	if err := runtimeDB.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := storage.InitRuntime(storage.LoaderConfig{
		BuiltinDB: builtinPath,
		RuntimeDB: runtimePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	results, _, err := search.Search(db, search.SearchQuery{
		Query: "积木报表",
		Type:  "vuln",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Name != "CVE-2023-1454" {
		t.Fatalf("results after InitRuntime = %v, want CVE-2023-1454", results)
	}
	contract, err := storage.GetMeta(db, "fts_contract_version")
	if err != nil {
		t.Fatal(err)
	}
	if contract != "go-security-tokenizer-v3" {
		t.Fatalf("fts_contract_version = %q, want go-security-tokenizer-v3", contract)
	}
}

func TestInitRuntimeFTSMigrationPreservesRuntimeOwnedResources(t *testing.T) {
	dir := t.TempDir()
	builtinPath := filepath.Join(dir, "builtin.db")
	runtimePath := filepath.Join(dir, "runtime", "runtime.db")

	builtinDB, err := storage.OpenDB(builtinPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SetMeta(builtinDB, "builtin_version", "test-v1"); err != nil {
		t.Fatal(err)
	}
	if err := builtinDB.Close(); err != nil {
		t.Fatal(err)
	}

	runtimeDB, err := storage.OpenDB(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SetMeta(runtimeDB, "builtin_version", "test-v1"); err != nil {
		t.Fatal(err)
	}
	if err := search.InsertResource(runtimeDB, search.Resource{
		Type:        "skill",
		Name:        "custom-search-guide",
		Source:      "custom",
		Description: "custommarker searchable knowledge",
	}); err != nil {
		t.Fatal(err)
	}
	if err := search.InsertResource(runtimeDB, search.Resource{
		Type:        "skill",
		Name:        "disabled-search-guide",
		Source:      "builtin",
		Description: "hiddenmarker searchable knowledge",
	}); err != nil {
		t.Fatal(err)
	}
	disabledBefore, err := search.GetByStableID(runtimeDB, "absec://builtin/skill/disabled-search-guide")
	if err != nil || disabledBefore == nil {
		t.Fatalf("get disabled resource before migration: resource=%v err=%v", disabledBefore, err)
	}
	if _, err := runtimeDB.Exec("UPDATE resources SET enabled=0 WHERE id=?", disabledBefore.ID); err != nil {
		t.Fatal(err)
	}
	if err := runtimeDB.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := storage.InitRuntime(storage.LoaderConfig{
		BuiltinDB: builtinPath,
		RuntimeDB: runtimePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	custom, _, err := search.Search(db, search.SearchQuery{
		Query: "custommarker",
		Type:  "skill",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(custom) != 1 || custom[0].Name != "custom-search-guide" || custom[0].Source != "custom" {
		t.Fatalf("custom resource after migration = %v", custom)
	}

	hidden, _, err := search.Search(db, search.SearchQuery{
		Query: "hiddenmarker",
		Type:  "skill",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hidden) != 0 {
		t.Fatalf("disabled resource became searchable after migration: %v", hidden)
	}
	disabledAfter, err := search.GetByStableID(db, "absec://builtin/skill/disabled-search-guide")
	if err != nil || disabledAfter == nil {
		t.Fatalf("get disabled resource after migration: resource=%v err=%v", disabledAfter, err)
	}
	if disabledAfter.ID != disabledBefore.ID {
		t.Fatalf("disabled resource ID changed from %d to %d", disabledBefore.ID, disabledAfter.ID)
	}
}
