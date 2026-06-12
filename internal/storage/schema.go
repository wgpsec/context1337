package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/ncruces/go-sqlite3/driver"
)

const schemaVersion = 1

const ddl = `
CREATE TABLE IF NOT EXISTS resources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT NOT NULL,
    name        TEXT NOT NULL,
    source      TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    category    TEXT,
    tags        TEXT,
    description TEXT,
    body        TEXT,
    metadata    TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    updated_at  TEXT DEFAULT (datetime('now')),
    enabled     INTEGER NOT NULL DEFAULT 1,
    UNIQUE(type, name, source)
);

CREATE INDEX IF NOT EXISTS idx_resources_type ON resources(type);
CREATE INDEX IF NOT EXISTS idx_resources_source ON resources(source);
CREATE INDEX IF NOT EXISTS idx_resources_category ON resources(type, category);

-- Self-contained FTS5 index: stores pre-tokenized text only (not original
-- content). The resources table keeps the raw text for display; write paths
-- explicitly populate this index with tokenized values, keeping rowid aligned
-- with resources.id. No external-content / triggers, so the raw body is never
-- overwritten by tokenized text.
CREATE VIRTUAL TABLE IF NOT EXISTS resources_fts USING fts5(
    name,
    description,
    tags,
    category,
    body,
    tokenize='unicode61'
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
`

// OpenDB opens (or creates) a SQLite database with the full schema.
// Uses WAL mode for concurrent reads.
func OpenDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}

	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)", path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if _, err := db.Exec(ddl); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	db.Exec("ALTER TABLE resources ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_resources_enabled ON resources(enabled)")

	return db, nil
}

// SetMeta stores a key-value pair in the meta table.
func SetMeta(db *sql.DB, key, value string) error {
	_, err := db.Exec("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", key, value)
	return err
}

// GetMeta retrieves a value from the meta table. Returns "" if not found.
func GetMeta(db *sql.DB, key string) (string, error) {
	var val string
	err := db.QueryRow("SELECT value FROM meta WHERE key = ?", key).Scan(&val)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return val, err
}

// CountByType returns resource counts grouped by type.
func CountByType(db *sql.DB) map[string]int {
	counts := make(map[string]int)
	rows, err := db.Query("SELECT type, COUNT(*) FROM resources GROUP BY type")
	if err != nil {
		return counts
	}
	defer rows.Close()
	for rows.Next() {
		var typ string
		var cnt int
		if rows.Scan(&typ, &cnt) == nil {
			counts[typ] = cnt
		}
	}
	return counts
}
