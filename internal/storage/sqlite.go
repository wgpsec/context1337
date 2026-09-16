package storage

import (
	"database/sql"
	"fmt"
	"net/url"

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

func openSQLite(path string, readOnly bool) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", sqliteFileDSN(path, readOnly))
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	return db, nil
}

func OpenReadOnly(path string) (*sql.DB, error) {
	return openSQLite(path, true)
}
