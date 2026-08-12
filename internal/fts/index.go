package fts

import (
	"database/sql"
	"fmt"

	"github.com/wgpsec/context1337/internal/tokenize"
)

const (
	ContractMetaKey = "fts_contract_version"
	ContractVersion = "go-security-tokenizer-v3"
)

type Executor interface {
	Exec(query string, args ...any) (sql.Result, error)
}

type Fields struct {
	Name        string
	Description string
	Tags        string
	Category    string
	Body        string
}

func Replace(executor Executor, id int64, fields Fields) error {
	if _, err := executor.Exec("DELETE FROM resources_fts WHERE rowid = ?", id); err != nil {
		return err
	}
	_, err := executor.Exec(`
		INSERT INTO resources_fts(rowid, name, description, tags, category, body)
			VALUES (?, ?, ?, ?, ?, ?)`,
			id,
			tokenize.TokenizeToString(fields.Name),
			tokenize.TokenizeToString(fields.Description),
			tokenize.TokenizeToString(fields.Tags),
			tokenize.TokenizeToString(fields.Category),
			tokenize.TokenizeToString(fields.Body),
	)
	return err
}

func Reindex(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT id, COALESCE(name,''), COALESCE(description,''), COALESCE(tags,''),
		       COALESCE(category,''), COALESCE(body,'')
		FROM resources ORDER BY id`)
	if err != nil {
		return fmt.Errorf("read resources for FTS reindex: %w", err)
	}

	type indexRow struct {
		id     int64
		fields Fields
	}
	resources := make([]indexRow, 0)
	for rows.Next() {
		var resource indexRow
		if err := rows.Scan(
			&resource.id,
			&resource.fields.Name,
			&resource.fields.Description,
			&resource.fields.Tags,
			&resource.fields.Category,
			&resource.fields.Body,
		); err != nil {
			rows.Close()
			return fmt.Errorf("scan resource for FTS reindex: %w", err)
		}
		resources = append(resources, resource)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate resources for FTS reindex: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close resources for FTS reindex: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin FTS reindex: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM resources_fts"); err != nil {
		return fmt.Errorf("clear FTS index: %w", err)
	}
	for _, resource := range resources {
		if err := Replace(tx, resource.id, resource.fields); err != nil {
			return fmt.Errorf("index resource %d: %w", resource.id, err)
		}
	}
	if _, err := tx.Exec(
		"INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
		ContractMetaKey,
		ContractVersion,
	); err != nil {
		return fmt.Errorf("write FTS contract version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit FTS reindex: %w", err)
	}
	return nil
}
