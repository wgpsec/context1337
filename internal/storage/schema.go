package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
)

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
    origin      TEXT NOT NULL DEFAULT '',
    format      TEXT NOT NULL DEFAULT '',
    vuln_type   TEXT,
    target_domain TEXT,
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

	db, err := openSQLite(path, false)
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec(ddl); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	// Both are migrations for databases created before the column existed. The
	// ALTER fails with "duplicate column name" on every open of a current
	// database, which is the expected steady state, so only the index is worth
	// reporting; a genuinely broken schema surfaces on the first query.
	_, _ = db.Exec("ALTER TABLE resources ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
	_, _ = db.Exec("ALTER TABLE resources ADD COLUMN origin TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE resources ADD COLUMN format TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE resources ADD COLUMN vuln_type TEXT")
	_, _ = db.Exec("ALTER TABLE resources ADD COLUMN target_domain TEXT")
	for _, index := range []string{
		"CREATE INDEX IF NOT EXISTS idx_resources_enabled ON resources(enabled)",
		"CREATE INDEX IF NOT EXISTS idx_resources_origin ON resources(type, origin)",
		"CREATE INDEX IF NOT EXISTS idx_resources_format ON resources(type, format)",
		"CREATE INDEX IF NOT EXISTS idx_resources_vuln_type ON resources(type, vuln_type)",
		"CREATE INDEX IF NOT EXISTS idx_resources_target_domain ON resources(type, target_domain)",
	} {
		if _, err := db.Exec(index); err != nil {
			return nil, fmt.Errorf("create resource index: %w", err)
		}
	}
	if err := backfillResourceFacets(db); err != nil {
		return nil, fmt.Errorf("backfill resource facets: %w", err)
	}

	return db, nil
}

// backfillResourceFacets gives pre-facet rows a source-agnostic origin/format
// and migrates the old category-only taxonomy. It only fills empty columns, so
// it is safe to run on every startup and preserves explicitly imported values.
func backfillResourceFacets(db *sql.DB) error {
	updates := []string{
		`UPDATE resources SET origin = 'platform',
		 format = CASE WHEN COALESCE(format, '') = '' THEN (CASE source WHEN 'builtin' THEN 'markdown' ELSE 'unknown' END) ELSE format END
		 WHERE COALESCE(origin, '') = '' AND source IN ('builtin', 'custom')`,
		`UPDATE resources SET origin = 'private',
		 format = CASE WHEN COALESCE(format, '') = '' THEN 'markdown' ELSE format END
		 WHERE COALESCE(origin, '') = '' AND source = 'team'`,
		`UPDATE resources SET origin = 'nuclei-official',
		 format = CASE WHEN COALESCE(format, '') = '' THEN 'nuclei-yaml' ELSE format END,
		 vuln_type = CASE category
		   WHEN 'nuclei-cve' THEN 'cve'
		   WHEN 'nuclei-cnvd' THEN 'cnvd'
		   WHEN 'nuclei-default-login' THEN 'default-login'
		   WHEN 'nuclei-misconfiguration' THEN 'misconfiguration'
		   WHEN 'nuclei-vulnerability' THEN 'vulnerability'
		   ELSE NULL END
		 WHERE COALESCE(origin, '') = '' AND source = 'nuclei'`,
		`UPDATE resources SET target_domain = category
		 WHERE type = 'vuln' AND COALESCE(target_domain, '') = ''
		   AND COALESCE(category, '') <> ''
		   AND source IN ('builtin', 'team')`,
	}
	for _, query := range updates {
		if _, err := db.Exec(query); err != nil {
			return err
		}
	}
	return nil
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
