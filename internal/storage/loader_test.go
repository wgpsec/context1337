package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoader_FirstBoot(t *testing.T) {
	dir := t.TempDir()
	builtinPath := filepath.Join(dir, "builtin.db")
	runtimePath := filepath.Join(dir, "runtime", "runtime.db")

	// Create a minimal builtin.db
	bdb, err := OpenDB(builtinPath)
	if err != nil {
		t.Fatal(err)
	}
	SetMeta(bdb, "builtin_version", "v1")
	bdb.Close()

	cfg := LoaderConfig{
		BuiltinDB: builtinPath,
		RuntimeDB: runtimePath,
	}

	db, err := InitRuntime(cfg)
	if err != nil {
		t.Fatalf("InitRuntime: %v", err)
	}
	defer db.Close()

	if _, err := os.Stat(runtimePath); os.IsNotExist(err) {
		t.Fatal("runtime.db not created")
	}

	ver, err := GetMeta(db, "builtin_version")
	if err != nil {
		t.Fatal(err)
	}
	if ver != "v1" {
		t.Errorf("version = %q, want v1", ver)
	}
}

func TestLoader_VersionMismatch(t *testing.T) {
	dir := t.TempDir()
	builtinPath := filepath.Join(dir, "builtin.db")
	runtimePath := filepath.Join(dir, "runtime", "runtime.db")

	bdb, err := OpenDB(builtinPath)
	if err != nil {
		t.Fatal(err)
	}
	SetMeta(bdb, "builtin_version", "v2")
	bdb.Close()

	os.MkdirAll(filepath.Dir(runtimePath), 0o755)
	rdb, err := OpenDB(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	SetMeta(rdb, "builtin_version", "v1")
	rdb.Close()

	cfg := LoaderConfig{
		BuiltinDB: builtinPath,
		RuntimeDB: runtimePath,
	}

	db, err := InitRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ver, _ := GetMeta(db, "builtin_version")
	if ver != "v2" {
		t.Errorf("version = %q, want v2 after rebuild", ver)
	}
}

func TestLoader_NormalRestart(t *testing.T) {
	dir := t.TempDir()
	builtinPath := filepath.Join(dir, "builtin.db")
	runtimePath := filepath.Join(dir, "runtime", "runtime.db")

	bdb, _ := OpenDB(builtinPath)
	SetMeta(bdb, "builtin_version", "v1")
	bdb.Close()

	os.MkdirAll(filepath.Dir(runtimePath), 0o755)
	rdb, _ := OpenDB(runtimePath)
	SetMeta(rdb, "builtin_version", "v1")
	rdb.Exec("INSERT INTO meta(key, value) VALUES('marker', 'keep')")
	rdb.Close()

	cfg := LoaderConfig{
		BuiltinDB: builtinPath,
		RuntimeDB: runtimePath,
	}

	db, err := InitRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	marker, _ := GetMeta(db, "marker")
	if marker != "keep" {
		t.Error("marker lost -- runtime.db was unexpectedly rebuilt")
	}
}

func TestLoader_NormalRestartSyncsNucleiWithoutDroppingRuntimeData(t *testing.T) {
	dir := t.TempDir()
	builtinPath := filepath.Join(dir, "builtin.db")
	runtimePath := filepath.Join(dir, "runtime", "runtime.db")
	nucleiDir := filepath.Join(dir, "nuclei-templates")

	bdb, err := OpenDB(builtinPath)
	if err != nil {
		t.Fatal(err)
	}
	SetMeta(bdb, "builtin_version", "v1")
	bdb.Close()

	os.MkdirAll(filepath.Dir(runtimePath), 0o755)
	rdb, err := OpenDB(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	SetMeta(rdb, "builtin_version", "v1")
	SetMeta(rdb, "marker", "keep")
	if _, err := rdb.Exec(`INSERT INTO resources
		(type, name, source, file_path, category, tags, description, body, metadata)
		VALUES ('skill', 'custom-skill', 'custom', '', 'web', 'custom', 'custom desc', 'custom body', '')`); err != nil {
		t.Fatal(err)
	}
	rdb.Close()

	writeNucleiTemplate(t, nucleiDir, "2024", "CVE-2024-0001.yaml", `id: CVE-2024-0001
info:
  name: Critical Test CVE
  severity: critical
  description: Critical test vulnerability.
  tags: test,rce
  metadata:
    vendor: acme
    product: widget
`)

	db, err := InitRuntime(LoaderConfig{
		BuiltinDB:         builtinPath,
		RuntimeDB:         runtimePath,
		NucleiDir:         nucleiDir,
		NucleiMinSeverity: "critical",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	marker, _ := GetMeta(db, "marker")
	if marker != "keep" {
		t.Fatal("marker lost -- runtime.db was unexpectedly rebuilt")
	}

	var customCount int
	if err := db.QueryRow("SELECT count(*) FROM resources WHERE source='custom'").Scan(&customCount); err != nil {
		t.Fatal(err)
	}
	if customCount != 1 {
		t.Fatalf("custom resource count = %d, want 1", customCount)
	}

	var nucleiCount int
	if err := db.QueryRow("SELECT count(*) FROM resources WHERE source='nuclei'").Scan(&nucleiCount); err != nil {
		t.Fatal(err)
	}
	if nucleiCount != 1 {
		t.Fatalf("nuclei resource count = %d, want 1", nucleiCount)
	}

	var ftsCount int
	if err := db.QueryRow(`SELECT count(*) FROM resources_fts f
		JOIN resources r ON r.id = f.rowid
		WHERE r.source='nuclei'`).Scan(&ftsCount); err != nil {
		t.Fatal(err)
	}
	if ftsCount != 1 {
		t.Fatalf("nuclei FTS count = %d, want 1", ftsCount)
	}
}

func TestLoader_NucleiConfigChangeReplacesOnlyNucleiRows(t *testing.T) {
	dir := t.TempDir()
	builtinPath := filepath.Join(dir, "builtin.db")
	runtimePath := filepath.Join(dir, "runtime", "runtime.db")
	nucleiDir := filepath.Join(dir, "nuclei-templates")

	bdb, err := OpenDB(builtinPath)
	if err != nil {
		t.Fatal(err)
	}
	SetMeta(bdb, "builtin_version", "v1")
	bdb.Close()

	writeNucleiTemplate(t, nucleiDir, "2024", "CVE-2024-0001.yaml", `id: CVE-2024-0001
info:
  name: Critical Test CVE
  severity: critical
  description: Critical test vulnerability.
  tags: test,rce
`)
	writeNucleiTemplate(t, nucleiDir, "2024", "CVE-2024-0002.yaml", `id: CVE-2024-0002
info:
  name: High Test CVE
  severity: high
  description: High test vulnerability.
  tags: test,web
`)

	db, err := InitRuntime(LoaderConfig{
		BuiltinDB:         builtinPath,
		RuntimeDB:         runtimePath,
		NucleiDir:         nucleiDir,
		NucleiMinSeverity: "critical",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO resources
		(type, name, source, file_path, category, tags, description, body, metadata)
		VALUES ('skill', 'custom-skill', 'custom', '', 'web', 'custom', 'custom desc', 'custom body', '')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db, err = InitRuntime(LoaderConfig{
		BuiltinDB:         builtinPath,
		RuntimeDB:         runtimePath,
		NucleiDir:         nucleiDir,
		NucleiMinSeverity: "high",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var nucleiCount int
	if err := db.QueryRow("SELECT count(*) FROM resources WHERE source='nuclei'").Scan(&nucleiCount); err != nil {
		t.Fatal(err)
	}
	if nucleiCount != 2 {
		t.Fatalf("nuclei resource count = %d, want 2", nucleiCount)
	}

	var customCount int
	if err := db.QueryRow("SELECT count(*) FROM resources WHERE source='custom'").Scan(&customCount); err != nil {
		t.Fatal(err)
	}
	if customCount != 1 {
		t.Fatalf("custom resource count = %d, want 1", customCount)
	}

	minSeverity, err := GetMeta(db, nucleiMinSeverityMetaKey)
	if err != nil {
		t.Fatal(err)
	}
	if minSeverity != "high" {
		t.Fatalf("nuclei min severity meta = %q, want high", minSeverity)
	}
}

func TestLoader_NucleiDisabledRemovesNucleiRows(t *testing.T) {
	dir := t.TempDir()
	builtinPath := filepath.Join(dir, "builtin.db")
	runtimePath := filepath.Join(dir, "runtime", "runtime.db")
	nucleiDir := filepath.Join(dir, "nuclei-templates")

	bdb, err := OpenDB(builtinPath)
	if err != nil {
		t.Fatal(err)
	}
	SetMeta(bdb, "builtin_version", "v1")
	bdb.Close()

	writeNucleiTemplate(t, nucleiDir, "2024", "CVE-2024-0001.yaml", `id: CVE-2024-0001
info:
  name: Critical Test CVE
  severity: critical
  description: Critical test vulnerability.
  tags: test,rce
`)

	db, err := InitRuntime(LoaderConfig{
		BuiltinDB:         builtinPath,
		RuntimeDB:         runtimePath,
		NucleiDir:         nucleiDir,
		NucleiMinSeverity: "critical",
	})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	db, err = InitRuntime(LoaderConfig{
		BuiltinDB: builtinPath,
		RuntimeDB: runtimePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var nucleiCount int
	if err := db.QueryRow("SELECT count(*) FROM resources WHERE source='nuclei'").Scan(&nucleiCount); err != nil {
		t.Fatal(err)
	}
	if nucleiCount != 0 {
		t.Fatalf("nuclei resource count = %d, want 0", nucleiCount)
	}

	dirMeta, err := GetMeta(db, nucleiDirMetaKey)
	if err != nil {
		t.Fatal(err)
	}
	if dirMeta != "" {
		t.Fatalf("nuclei dir meta = %q, want empty", dirMeta)
	}
}

func TestLoader_NucleiDisabledRemovesLegacyRowsWithoutMeta(t *testing.T) {
	dir := t.TempDir()
	builtinPath := filepath.Join(dir, "builtin.db")
	runtimePath := filepath.Join(dir, "runtime", "runtime.db")

	bdb, err := OpenDB(builtinPath)
	if err != nil {
		t.Fatal(err)
	}
	SetMeta(bdb, "builtin_version", "v1")
	bdb.Close()

	os.MkdirAll(filepath.Dir(runtimePath), 0o755)
	rdb, err := OpenDB(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	SetMeta(rdb, "builtin_version", "v1")
	if err := insertResourceWithMeta(rdb, "vuln", "CVE-2024-0001", "nuclei", "/tmp/CVE-2024-0001.yaml",
		"nuclei-cve", "test", "legacy nuclei vuln", "legacy nuclei body", `{"severity":"CRITICAL"}`); err != nil {
		t.Fatal(err)
	}
	rdb.Close()

	db, err := InitRuntime(LoaderConfig{
		BuiltinDB: builtinPath,
		RuntimeDB: runtimePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var nucleiCount int
	if err := db.QueryRow("SELECT count(*) FROM resources WHERE source='nuclei'").Scan(&nucleiCount); err != nil {
		t.Fatal(err)
	}
	if nucleiCount != 0 {
		t.Fatalf("nuclei resource count = %d, want 0", nucleiCount)
	}

	var ftsCount int
	if err := db.QueryRow("SELECT count(*) FROM resources_fts").Scan(&ftsCount); err != nil {
		t.Fatal(err)
	}
	if ftsCount != 0 {
		t.Fatalf("FTS count = %d, want 0", ftsCount)
	}
}

func TestLoader_TeamDictMetadata(t *testing.T) {
	dir := t.TempDir()
	builtinPath := filepath.Join(dir, "builtin.db")
	runtimeDir := filepath.Join(dir, "runtime")
	os.MkdirAll(runtimeDir, 0o755)
	runtimePath := filepath.Join(runtimeDir, "runtime.db")

	bdb, err := OpenDB(builtinPath)
	if err != nil {
		t.Fatal(err)
	}
	SetMeta(bdb, "builtin_version", "v1")
	bdb.Close()

	teamDir := filepath.Join(dir, "team")
	dicDir := filepath.Join(teamDir, "Dic", "auth", "password")
	os.MkdirAll(dicDir, 0o755)

	os.WriteFile(filepath.Join(dicDir, "_meta.yaml"), []byte("category: auth\ntags: \"password,brute-force\"\nfiles:\n  - name: top10.txt\n    description: \"Top 10 passwords\"\n    tags: \"common\"\n"), 0o644)
	os.WriteFile(filepath.Join(dicDir, "top10.txt"), []byte("admin\npassword\n123456\n"), 0o644)

	db, err := InitRuntime(LoaderConfig{
		BuiltinDB: builtinPath,
		RuntimeDB: runtimePath,
		TeamDir:   teamDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var desc, tags string
	err = db.QueryRow("SELECT description, tags FROM resources WHERE type='dict' AND source='team'").Scan(&desc, &tags)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if desc == "" {
		t.Error("expected description from _meta.yaml")
	}
	if tags == "" {
		t.Error("expected tags from _meta.yaml")
	}
}

func writeNucleiTemplate(t *testing.T, nucleiDir, year, filename, content string) {
	t.Helper()
	dir := filepath.Join(nucleiDir, "http", "cves", year)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanAndIndex_Vulns(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "runtime.db")
	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()

	// Create team vuln directory
	teamDir := filepath.Join(dir, "team")
	vulnDir := filepath.Join(teamDir, "Vuln", "middleware", "apache-log4j")
	os.MkdirAll(vulnDir, 0o755)
	os.WriteFile(filepath.Join(vulnDir, "CVE-2021-44228.md"), []byte(`---
id: CVE-2021-44228
title: Log4j RCE
description: JNDI injection leads to RCE
product: Apache Log4j
vendor: Apache
version_affected: "<2.17.0"
severity: CRITICAL
tags: [rce, jndi]
fingerprint: ["header=X-Log4j", "log4j"]
---

## PoC
test payload
`), 0o644)

	err = scanAndIndex(db, LoaderConfig{TeamDir: teamDir})
	if err != nil {
		t.Fatalf("scanAndIndex: %v", err)
	}

	var count int
	db.QueryRow("SELECT count(*) FROM resources WHERE type='vuln'").Scan(&count)
	if count != 1 {
		t.Fatalf("vuln count = %d, want 1", count)
	}

	var name, metadata string
	db.QueryRow("SELECT name, metadata FROM resources WHERE type='vuln'").Scan(&name, &metadata)
	if name != "CVE-2021-44228" {
		t.Errorf("name = %q", name)
	}
	if !strings.Contains(metadata, "CRITICAL") {
		t.Errorf("metadata missing severity: %s", metadata)
	}
	if !strings.Contains(metadata, "header=X-Log4j,log4j") {
		t.Errorf("metadata missing array fingerprint: %s", metadata)
	}
}

func writeTeamVuln(t *testing.T, teamDir, product, id, description, fingerprintYAML string) {
	t.Helper()
	vulnDir := filepath.Join(teamDir, "Vuln", "web", product)
	if err := os.MkdirAll(vulnDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf(`---
id: %s
title: %s
description: %s
product: %s
vendor: NCSEC
version_affected: "lab-fixture"
severity: LOW
tags: [info_leak]
fingerprint: %s
---

## 漏洞描述

%s
`, id, id, description, product, fingerprintYAML, description)
	if err := os.WriteFile(filepath.Join(vulnDir, id+".md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoader_TeamSyncOnRestartKeepsIDsWhenUnchanged(t *testing.T) {
	dir := t.TempDir()
	builtinPath := filepath.Join(dir, "builtin.db")
	runtimePath := filepath.Join(dir, "runtime", "runtime.db")
	teamDir := filepath.Join(dir, "team")

	bdb, err := OpenDB(builtinPath)
	if err != nil {
		t.Fatal(err)
	}
	SetMeta(bdb, "builtin_version", "v1")
	bdb.Close()

	writeTeamVuln(t, teamDir, "ncsec-lab-board", "NCSEC-PRIV-0001", "first fixture", `["ncsec-lab-board", "NCSEC-PRIV-0001"]`)

	cfg := LoaderConfig{BuiltinDB: builtinPath, RuntimeDB: runtimePath, TeamDir: teamDir}
	db, err := InitRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var firstID int
	if err := db.QueryRow("SELECT id FROM resources WHERE source='team' AND name='NCSEC-PRIV-0001'").Scan(&firstID); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db, err = InitRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var secondID, count int
	if err := db.QueryRow("SELECT id FROM resources WHERE source='team' AND name='NCSEC-PRIV-0001'").Scan(&secondID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT count(*) FROM resources WHERE source='team'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("team count = %d, want 1", count)
	}
	if secondID != firstID {
		t.Fatalf("team resource id changed from %d to %d on unchanged restart", firstID, secondID)
	}
}

func TestLoader_TeamSyncPicksUpNewContentWithoutRebuildingRuntime(t *testing.T) {
	dir := t.TempDir()
	builtinPath := filepath.Join(dir, "builtin.db")
	runtimePath := filepath.Join(dir, "runtime", "runtime.db")
	teamDir := filepath.Join(dir, "team")

	bdb, err := OpenDB(builtinPath)
	if err != nil {
		t.Fatal(err)
	}
	SetMeta(bdb, "builtin_version", "v1")
	bdb.Close()

	os.MkdirAll(filepath.Dir(runtimePath), 0o755)
	rdb, err := OpenDB(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	SetMeta(rdb, "builtin_version", "v1")
	SetMeta(rdb, "marker", "keep")
	if _, err := rdb.Exec(`INSERT INTO resources
		(type, name, source, file_path, category, tags, description, body, metadata)
		VALUES ('skill', 'custom-skill', 'custom', '', 'web', 'custom', 'custom desc', 'custom body', '')`); err != nil {
		t.Fatal(err)
	}
	rdb.Close()

	writeTeamVuln(t, teamDir, "ncsec-lab-board", "NCSEC-PRIV-0001", "first fixture", `["ncsec-lab-board"]`)

	cfg := LoaderConfig{BuiltinDB: builtinPath, RuntimeDB: runtimePath, TeamDir: teamDir}
	db, err := InitRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	writeTeamVuln(t, teamDir, "ncsec-lab-board", "NCSEC-PRIV-0001", "updated fixture", `["ncsec-lab-board"]`)
	writeTeamVuln(t, teamDir, "ncsec-lab-board", "NCSEC-PRIV-0002", "second fixture", `["ncsec-lab-board"]`)

	db, err = InitRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	marker, _ := GetMeta(db, "marker")
	if marker != "keep" {
		t.Fatal("marker lost -- runtime.db was unexpectedly rebuilt")
	}

	var customCount, teamCount int
	if err := db.QueryRow("SELECT count(*) FROM resources WHERE source='custom'").Scan(&customCount); err != nil {
		t.Fatal(err)
	}
	if customCount != 1 {
		t.Fatalf("custom resource count = %d, want 1", customCount)
	}
	if err := db.QueryRow("SELECT count(*) FROM resources WHERE source='team'").Scan(&teamCount); err != nil {
		t.Fatal(err)
	}
	if teamCount != 2 {
		t.Fatalf("team resource count = %d, want 2", teamCount)
	}

	var desc string
	if err := db.QueryRow("SELECT description FROM resources WHERE source='team' AND name='NCSEC-PRIV-0001'").Scan(&desc); err != nil {
		t.Fatal(err)
	}
	if desc != "updated fixture" {
		t.Fatalf("updated description = %q, want updated fixture", desc)
	}
}
