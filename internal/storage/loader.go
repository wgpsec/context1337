package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/wgpsec/context1337/internal/fts"
)

// LoaderConfig defines paths for the startup loader.
type LoaderConfig struct {
	BuiltinDB         string
	RuntimeDB         string
	TeamDir           string
	NucleiDir         string
	NucleiMinSeverity string
}

const (
	nucleiDirMetaKey         = "nuclei_dir"
	nucleiMinSeverityMetaKey = "nuclei_min_severity"
	nucleiCountMetaKey       = "nuclei_count"
)

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

	if err := syncNucleiSource(db, cfg); err != nil {
		db.Close()
		return nil, fmt.Errorf("sync nuclei data: %w", err)
	}

	contractVersion, err := GetMeta(db, fts.ContractMetaKey)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("read FTS contract version: %w", err)
	}
	if contractVersion != fts.ContractVersion {
		log.Printf("loader: migrating FTS contract from %q to %q", contractVersion, fts.ContractVersion)
		if err := fts.Reindex(db); err != nil {
			db.Close()
			return nil, fmt.Errorf("migrate FTS contract: %w", err)
		}
	}

	return db, nil
}

// insertResource inserts a resource directly via SQL, avoiding an import cycle
// with the search package. The resources table keeps the RAW text for display;
// the FTS index gets pre-tokenized text (jieba-equivalent) so unicode61 can
// match CJK. Keeping the two apart is why detail views return readable content.
func insertResource(db *sql.DB, typ, name, source, filePath, category, tags, description, body string) error {
	return insertResourceWithMeta(db, typ, name, source, filePath, category, tags, description, body, "")
}

// insertResourceWithMeta inserts a resource with a metadata JSON blob.
func insertResourceWithMeta(db *sql.DB, typ, name, source, filePath, category, tags, description, body, metadata string) error {
	res, err := db.Exec(`
		INSERT OR REPLACE INTO resources
			(type, name, source, file_path, category, tags, description, body, metadata, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		typ, name, source, filePath, category, tags, description, body, metadata,
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	return indexResourceFTS(db, id, name, description, tags, category, body)
}

// indexResourceFTS (re)populates the self-contained FTS row for a resource.
// Every searchable field uses the shared tokenizer so indexing and query
// planning follow one contract. rowid is aligned with resources.id.
func indexResourceFTS(db *sql.DB, id int64, name, description, tags, category, body string) error {
	return fts.Replace(db, id, fts.Fields{
		Name: name, Description: description, Tags: tags, Category: category, Body: body,
	})
}

func scanAndIndex(db *sql.DB, cfg LoaderConfig) error {
	if cfg.TeamDir == "" {
		return nil
	}

	dirs := map[string]string{
		"skills":   filepath.Join(cfg.TeamDir, "skills"),
		"dicts":    filepath.Join(cfg.TeamDir, "Dic"),
		"payloads": filepath.Join(cfg.TeamDir, "Payload"),
		"vulns":    filepath.Join(cfg.TeamDir, "Vuln"),
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
				s.Category, s.Tags, s.Description, s.Body)
		}
	}

	if info, err := os.Stat(dirs["dicts"]); err == nil && info.IsDir() {
		dicts, err := ScanDicts(dirs["dicts"])
		if err != nil {
			log.Printf("loader: scan team dicts: %v", err)
		}
		for _, d := range dicts {
			insertResource(db, "dict", d.Path, "team", d.FilePath,
				d.Category, d.Tags, d.Description, "")
		}
	}

	if info, err := os.Stat(dirs["payloads"]); err == nil && info.IsDir() {
		payloads, err := ScanPayloads(dirs["payloads"])
		if err != nil {
			log.Printf("loader: scan team payloads: %v", err)
		}
		for _, p := range payloads {
			insertResource(db, "payload", p.Path, "team", p.FilePath,
				p.Category, p.Tags, p.Description, "")
		}
	}

	if info, err := os.Stat(dirs["vulns"]); err == nil && info.IsDir() {
		vulns, err := ScanVulns(dirs["vulns"])
		if err != nil {
			log.Printf("loader: scan team vulns: %v", err)
		}
		for _, v := range vulns {
			metaObj := map[string]string{
				"severity":         v.Severity,
				"product":          v.Product,
				"vendor":           v.Vendor,
				"version_affected": v.VersionAffected,
				"fingerprint":      v.Fingerprint,
			}
			metaJSON, _ := json.Marshal(metaObj)
			if err := insertResourceWithMeta(db, "vuln", v.ID, "team", v.FilePath,
				v.Category, v.Tags, v.Description, v.Body, string(metaJSON)); err != nil {
				log.Printf("loader: insert team vuln %s: %v", v.ID, err)
			}
		}
	}

	return nil
}

func syncNucleiSource(db *sql.DB, cfg LoaderConfig) error {
	nucleiDir, err := normalizeNucleiDir(cfg.NucleiDir)
	if err != nil {
		return err
	}
	minSeverity := normalizeNucleiMinSeverity(cfg.NucleiMinSeverity)

	currentDir, err := GetMeta(db, nucleiDirMetaKey)
	if err != nil {
		return err
	}
	currentMinSeverity, err := GetMeta(db, nucleiMinSeverityMetaKey)
	if err != nil {
		return err
	}
	currentCountMeta, err := GetMeta(db, nucleiCountMetaKey)
	if err != nil {
		return err
	}

	if nucleiDir == "" {
		count, err := countNucleiResources(db)
		if err != nil {
			return err
		}
		if currentDir == "" && currentMinSeverity == "" && count == 0 {
			return nil
		}
		if err := deleteNucleiResources(db); err != nil {
			return err
		}
		if err := clearNucleiMeta(db); err != nil {
			return err
		}
		log.Println("loader: nuclei data disabled; removed source=nuclei resources")
		return nil
	}

	if currentDir == nucleiDir && currentMinSeverity == minSeverity {
		count, err := countNucleiResources(db)
		if err != nil {
			return err
		}
		if currentCountMeta == fmt.Sprintf("%d", count) {
			log.Printf("loader: nuclei data up to date: %d vulns", count)
			return nil
		}
	}

	nvulns, err := ScanNucleiVulns(nucleiDir, minSeverity)
	if err != nil {
		return err
	}

	if err := deleteNucleiResources(db); err != nil {
		return err
	}

	for _, v := range nvulns {
		metaObj := map[string]string{
			"severity": v.Severity,
			"product":  v.Product,
			"vendor":   v.Vendor,
		}
		metaJSON, _ := json.Marshal(metaObj)
		if err := insertResourceWithMeta(db, "vuln", v.ID, "nuclei", v.FilePath,
			v.Category, v.Tags, v.Description, v.Body, string(metaJSON)); err != nil {
			return fmt.Errorf("insert nuclei vuln %s: %w", v.ID, err)
		}
	}
	if err := SetMeta(db, nucleiDirMetaKey, nucleiDir); err != nil {
		return err
	}
	if err := SetMeta(db, nucleiMinSeverityMetaKey, minSeverity); err != nil {
		return err
	}
	if err := SetMeta(db, nucleiCountMetaKey, fmt.Sprintf("%d", len(nvulns))); err != nil {
		return err
	}
	log.Printf("loader: nuclei vulns indexed: %d", len(nvulns))
	return nil
}

func normalizeNucleiDir(dir string) (string, error) {
	if dir == "" {
		return "", nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func normalizeNucleiMinSeverity(severity string) string {
	if severity == "" {
		return "high"
	}
	return strings.ToLower(severity)
}

func deleteNucleiResources(db *sql.DB) error {
	if _, err := db.Exec(`DELETE FROM resources_fts
		WHERE rowid IN (SELECT id FROM resources WHERE source = 'nuclei')`); err != nil {
		return err
	}
	_, err := db.Exec("DELETE FROM resources WHERE source = 'nuclei'")
	return err
}

func countNucleiResources(db *sql.DB) (int, error) {
	var count int
	err := db.QueryRow("SELECT count(*) FROM resources WHERE source = 'nuclei'").Scan(&count)
	return count, err
}

func clearNucleiMeta(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM meta WHERE key IN (?, ?, ?)",
		nucleiDirMetaKey, nucleiMinSeverityMetaKey, nucleiCountMetaKey)
	return err
}

func readBuiltinVersion(path string) (string, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", nil
	}
	db, err := openSQLite(path, true)
	if err != nil {
		return "", err
	}
	defer db.Close()
	return GetMeta(db, "builtin_version")
}

func readRuntimeVersion(path string) (string, error) {
	db, err := openSQLite(path, true)
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
