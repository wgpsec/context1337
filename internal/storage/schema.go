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
    mitre       TEXT,
    difficulty  TEXT,
    description TEXT,
    body        TEXT,
    metadata    TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    updated_at  TEXT DEFAULT (datetime('now')),
    UNIQUE(type, name, source)
);

CREATE INDEX IF NOT EXISTS idx_resources_type ON resources(type);
CREATE INDEX IF NOT EXISTS idx_resources_source ON resources(source);
CREATE INDEX IF NOT EXISTS idx_resources_category ON resources(type, category);

CREATE VIRTUAL TABLE IF NOT EXISTS resources_fts USING fts5(
    name,
    description,
    tags,
    category,
    mitre,
    body,
    content='resources',
    content_rowid='id'
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- Triggers to keep FTS in sync with resources
CREATE TRIGGER IF NOT EXISTS resources_ai AFTER INSERT ON resources BEGIN
    INSERT INTO resources_fts(rowid, name, description, tags, category, mitre, body)
    VALUES (new.id, new.name, new.description, new.tags, new.category, new.mitre, new.body);
END;

CREATE TRIGGER IF NOT EXISTS resources_ad AFTER DELETE ON resources BEGIN
    INSERT INTO resources_fts(resources_fts, rowid, name, description, tags, category, mitre, body)
    VALUES ('delete', old.id, old.name, old.description, old.tags, old.category, old.mitre, old.body);
END;

CREATE TRIGGER IF NOT EXISTS resources_au AFTER UPDATE ON resources BEGIN
    INSERT INTO resources_fts(resources_fts, rowid, name, description, tags, category, mitre, body)
    VALUES ('delete', old.id, old.name, old.description, old.tags, old.category, old.mitre, old.body);
    INSERT INTO resources_fts(rowid, name, description, tags, category, mitre, body)
    VALUES (new.id, new.name, new.description, new.tags, new.category, new.mitre, new.body);
END;
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
