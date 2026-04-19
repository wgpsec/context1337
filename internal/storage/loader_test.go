package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoader_FirstBoot(t *testing.T) {
	dir := t.TempDir()
	builtinPath := filepath.Join(dir, "builtin.db")
	runtimePath := filepath.Join(dir, "runtime", "runtime.db")
	skillsDir := filepath.Join(dir, "skills")

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
		SkillsDir: skillsDir,
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
