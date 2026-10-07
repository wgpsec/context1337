package storage

import (
	"database/sql"
	"fmt"
	"net/url"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func sqliteFileDSN(path string, readOnly bool) string {
	query := url.Values{}
	query.Set("_busy_timeout", "5000")
	if readOnly {
		query.Set("mode", "ro")
	} else {
		query.Set("_journal_mode", "WAL")
		query.Set("_foreign_keys", "1")
	}
	return fmt.Sprintf("file:%s?%s", path, query.Encode())
}

// Connection pool bounds. Left unset, every concurrent request opens its own
// SQLite connection; each go-sqlite3 connection is a full handle with its own
// page cache, and the k8s deployment sets no resource limits, so the failure
// mode is OOMKill rather than a clean error. WAL serialises writers but allows
// readers to proceed concurrently, so the ceiling is generous enough for
// reader parallelism and small enough to stay bounded.
const (
	maxOpenConns = 8
	maxIdleConns = 4
	// Long-lived idle connections pin WAL read marks and block checkpointing,
	// so hand them back periodically instead of holding them for process life.
	connMaxLifetime = 30 * time.Minute
)

func openSQLite(path string, readOnly bool) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", sqliteFileDSN(path, readOnly))
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// Must stay above 1: a handler that iterates rows while issuing another
	// query would deadlock against itself with a single connection.
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	return db, nil
}

func OpenReadOnly(path string) (*sql.DB, error) {
	return openSQLite(path, true)
}
