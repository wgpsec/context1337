package storage

import (
	"path/filepath"
	"testing"
)

func TestOpenDB_CreatesSchema(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()

	// Verify resources table exists
	var count int
	err = db.QueryRow("SELECT count(*) FROM resources").Scan(&count)
	if err != nil {
		t.Fatalf("resources table missing: %v", err)
	}

	// Verify FTS5 table exists
	err = db.QueryRow("SELECT count(*) FROM resources_fts").Scan(&count)
	if err != nil {
		t.Fatalf("resources_fts table missing: %v", err)
	}
}

func TestOpenDB_WALMode(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()

	var mode string
	err = db.QueryRow("PRAGMA journal_mode").Scan(&mode)
	if err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
}

func TestSetGetMeta(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := SetMeta(db, "version", "1"); err != nil {
		t.Fatal(err)
	}
	v, err := GetMeta(db, "version")
	if err != nil {
		t.Fatal(err)
	}
	if v != "1" {
		t.Errorf("got %q, want 1", v)
	}

	// Non-existent key
	v, err = GetMeta(db, "missing")
	if err != nil {
		t.Fatal(err)
	}
	if v != "" {
		t.Errorf("got %q, want empty", v)
	}
}

func TestOpenDB_BusyTimeout(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()

	var timeout int
	if err := db.QueryRow("PRAGMA busy_timeout").Scan(&timeout); err != nil {
		t.Fatal(err)
	}
	if timeout != 5000 {
		t.Fatalf("busy_timeout = %d, want 5000", timeout)
	}
}

func TestOpenDB_JSONExtract(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()

	var severity string
	err = db.QueryRow(`SELECT json_extract('{"severity":"high"}', '$.severity')`).Scan(&severity)
	if err != nil {
		t.Fatalf("json_extract: %v", err)
	}
	if severity != "high" {
		t.Fatalf("json_extract = %q, want high", severity)
	}
}

// The pool is bounded because the k8s deployment sets no container resource
// limits: an unbounded pool turns a traffic spike into an OOMKill instead of
// backpressure. It must also stay above a single connection, since a handler
// that reads rows while issuing another query would otherwise deadlock here.
func TestOpenDB_BoundsConnectionPool(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()

	if got := db.Stats().MaxOpenConnections; got <= 1 || got > 64 {
		t.Fatalf("MaxOpenConnections = %d, want a bounded pool above a single connection", got)
	}
}

func TestOpenSQLite_ReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	db, err := OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	if err := SetMeta(db, "builtin_version", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	ro, err := openSQLite(path, true)
	if err != nil {
		t.Fatalf("openSQLite read-only: %v", err)
	}
	defer ro.Close()

	got, err := GetMeta(ro, "builtin_version")
	if err != nil {
		t.Fatal(err)
	}
	if got != "v1" {
		t.Fatalf("builtin_version = %q, want v1", got)
	}
}

func TestBackfillResourceFacets(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "facets.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`INSERT INTO resources (type, name, source, file_path, category)
		VALUES
		('vuln', 'CVE-2026-1', 'nuclei', 'x.yaml', 'nuclei-cve'),
		('vuln', 'PRIVATE-1', 'team', 'x.md', 'web'),
		('skill', 'team-skill', 'team', 'SKILL.md', 'recon')`)
	if err != nil {
		t.Fatalf("insert resources: %v", err)
	}
	if err := backfillResourceFacets(db); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	var origin, format, vulnType, targetDomain string
	err = db.QueryRow(`SELECT origin, format, COALESCE(vuln_type, ''), COALESCE(target_domain, '')
		FROM resources WHERE name = 'CVE-2026-1'`).Scan(&origin, &format, &vulnType, &targetDomain)
	if err != nil {
		t.Fatalf("read nuclei facets: %v", err)
	}
	if origin != "nuclei-official" || format != "nuclei-yaml" || vulnType != "cve" || targetDomain != "" {
		t.Fatalf("nuclei facets = %q/%q/%q/%q", origin, format, vulnType, targetDomain)
	}

	err = db.QueryRow(`SELECT origin, format, COALESCE(vuln_type, ''), COALESCE(target_domain, '')
		FROM resources WHERE name = 'PRIVATE-1'`).Scan(&origin, &format, &vulnType, &targetDomain)
	if err != nil {
		t.Fatalf("read private facets: %v", err)
	}
	if origin != "private" || format != "markdown" || vulnType != "" || targetDomain != "web" {
		t.Fatalf("private facets = %q/%q/%q/%q", origin, format, vulnType, targetDomain)
	}
}

func TestOpenDBMigratesLegacyResourcesTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := openSQLite(path, false)
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	_, err = legacy.Exec(`CREATE TABLE resources (
		id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, name TEXT NOT NULL,
		source TEXT NOT NULL, file_path TEXT NOT NULL, category TEXT, tags TEXT,
		description TEXT, body TEXT, metadata TEXT, enabled INTEGER NOT NULL DEFAULT 1)`)
	if err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy: %v", err)
	}

	db, err := OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB legacy: %v", err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT count(*) FROM resources").Scan(&count); err != nil {
		t.Fatalf("query migrated resources: %v", err)
	}
}
