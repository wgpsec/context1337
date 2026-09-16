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

func TestOpenDB_DoesNotLimitConnections(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()

	if got := db.Stats().MaxOpenConnections; got != 0 {
		t.Fatalf("MaxOpenConnections = %d, want 0 (unlimited)", got)
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
