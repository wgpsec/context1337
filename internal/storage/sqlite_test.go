package storage

import (
	"strings"
	"testing"
)

func TestSqliteFileDSN_ReadWrite(t *testing.T) {
	dsn := sqliteFileDSN("/tmp/runtime.db", false)
	for _, want := range []string{
		"file:/tmp/runtime.db?",
		"_journal_mode=WAL",
		"_busy_timeout=5000",
		"_foreign_keys=1",
	} {
		if !strings.Contains(dsn, want) {
			t.Fatalf("dsn %q missing %q", dsn, want)
		}
	}
	if strings.Contains(dsn, "mode=ro") {
		t.Fatalf("read-write dsn unexpectedly read-only: %q", dsn)
	}
}

func TestSqliteFileDSN_ReadOnly(t *testing.T) {
	dsn := sqliteFileDSN("/tmp/builtin.db", true)
	for _, want := range []string{
		"file:/tmp/builtin.db?",
		"mode=ro",
		"_busy_timeout=5000",
	} {
		if !strings.Contains(dsn, want) {
			t.Fatalf("dsn %q missing %q", dsn, want)
		}
	}
	if strings.Contains(dsn, "_journal_mode") {
		t.Fatalf("read-only dsn set journal_mode: %q", dsn)
	}
}
