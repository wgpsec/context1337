package storage

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/Esonhugh/context1337/internal/tokenize"
)

// LoaderConfig defines paths for the startup loader.
type LoaderConfig struct {
	BuiltinDB string
	RuntimeDB string
	TeamDir   string
}

// InitRuntime handles the three-layer startup lifecycle:
// 1. If runtime.db doesn't exist -> copy builtin.db -> scan team data
// 2. If builtin version changed -> rebuild runtime.db from new builtin
// 3. Otherwise -> open existing runtime.db (instant start)
func InitRuntime(cfg LoaderConfig) (*sql.DB, error) {
	needRebuild := false

	_, err := os.Stat(cfg.RuntimeDB)
	runtimeExists := err == nil

	if !runtimeExists {
		needRebuild = true
	} else {
		builtinVer, err := readBuiltinVersion(cfg.BuiltinDB)
		if err != nil {
			return nil, fmt.Errorf("read builtin version: %w", err)
		}
		runtimeVer, err := readRuntimeVersion(cfg.RuntimeDB)
		if err != nil {
			return nil, fmt.Errorf("read runtime version: %w", err)
		}
		if builtinVer != runtimeVer {
			needRebuild = true
		}
	}

	if needRebuild {
		log.Println("loader: rebuilding runtime.db")
		if err := os.MkdirAll(filepath.Dir(cfg.RuntimeDB), 0o755); err != nil {
			return nil, err
		}
		os.Remove(cfg.RuntimeDB)
		os.Remove(cfg.RuntimeDB + "-wal")
		os.Remove(cfg.RuntimeDB + "-shm")

		if _, err := os.Stat(cfg.BuiltinDB); err == nil {
			if err := copyFile(cfg.BuiltinDB, cfg.RuntimeDB); err != nil {
				return nil, fmt.Errorf("copy builtin: %w", err)
			}
		}
	}

	db, err := OpenDB(cfg.RuntimeDB)
	if err != nil {
		return nil, err
	}

	if needRebuild {
		if err := scanAndIndex(db, cfg); err != nil {
			db.Close()
			return nil, fmt.Errorf("scan team data: %w", err)
		}
	}

	return db, nil
}

// insertResource inserts a resource directly via SQL, avoiding an import cycle
// with the search package. Description and body are pre-tokenized for FTS5
// consistency with the Python build-time indexer (jieba).
func insertResource(db *sql.DB, typ, name, source, filePath, category, tags, mitre, difficulty, description, body string) error {
	tokDesc := tokenize.TokenizeToString(description)
	tokBody := tokenize.TokenizeToString(body)
	_, err := db.Exec(`
		INSERT OR REPLACE INTO resources
			(type, name, source, file_path, category, tags, mitre, difficulty, description, body, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		typ, name, source, filePath, category, tags, mitre, difficulty, tokDesc, tokBody,
	)
	return err
}

func scanAndIndex(db *sql.DB, cfg LoaderConfig) error {
	if cfg.TeamDir == "" {
		return nil
	}

	dirs := map[string]string{
		"skills":   filepath.Join(cfg.TeamDir, "skills"),
		"dicts":    filepath.Join(cfg.TeamDir, "Dic"),
		"payloads": filepath.Join(cfg.TeamDir, "Payload"),
		"tools":    filepath.Join(cfg.TeamDir, "Tools"),
	}
	// Resolve symlinks so filepath.Walk descends into linked directories
	for k, v := range dirs {
		if resolved, err := filepath.EvalSymlinks(v); err == nil {
			dirs[k] = resolved
		}
	}

	if info, err := os.Stat(dirs["skills"]); err == nil && info.IsDir() {
		skills, err := ScanSkills(dirs["skills"])
		if err != nil {
			log.Printf("loader: scan team skills: %v", err)
		}
		for _, s := range skills {
			insertResource(db, "skill", s.Name, "team", s.FilePath,
				s.Category, s.Tags, "", s.Difficulty, s.Description, s.Body)
		}
	}

	if info, err := os.Stat(dirs["dicts"]); err == nil && info.IsDir() {
		dicts, err := ScanDicts(dirs["dicts"])
		if err != nil {
			log.Printf("loader: scan team dicts: %v", err)
		}
		for _, d := range dicts {
			insertResource(db, "dict", d.Path, "team", d.FilePath,
				d.Category, d.Tags, "", "", d.Description, "")
		}
	}

	if info, err := os.Stat(dirs["payloads"]); err == nil && info.IsDir() {
		payloads, err := ScanPayloads(dirs["payloads"])
		if err != nil {
			log.Printf("loader: scan team payloads: %v", err)
		}
		for _, p := range payloads {
			insertResource(db, "payload", p.Path, "team", p.FilePath,
				p.Category, p.Tags, "", "", p.Description, "")
		}
	}

	if info, err := os.Stat(dirs["tools"]); err == nil && info.IsDir() {
		tools, err := ScanTools(dirs["tools"])
		if err != nil {
			log.Printf("loader: scan team tools: %v", err)
		}
		for _, t := range tools {
			metadata := fmt.Sprintf(`{"binary":"%s","homepage":"%s"}`, t.Binary, t.Homepage)
			insertResource(db, "tool", t.ID, "team", t.FilePath,
				t.Category, "", "", "", t.Description, t.RawYAML)
			// Update metadata separately
			db.Exec("UPDATE resources SET metadata=? WHERE type='tool' AND name=? AND source='team'", metadata, t.ID)
		}
	}

	return nil
}

func readBuiltinVersion(path string) (string, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", nil
	}
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro", path))
	if err != nil {
		return "", err
	}
	defer db.Close()
	return GetMeta(db, "builtin_version")
}

func readRuntimeVersion(path string) (string, error) {
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro", path))
	if err != nil {
		return "", err
	}
	defer db.Close()
	return GetMeta(db, "builtin_version")
}

func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()

	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer d.Close()

	_, err = io.Copy(d, s)
	return err
}
