package storage

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testdataDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata")
}

func TestParseSkillMD(t *testing.T) {
	path := filepath.Join(testdataDir(), "skills", "sql-injection", "SKILL.md")
	skill, err := ParseSkillMD(path)
	if err != nil {
		t.Fatalf("ParseSkillMD: %v", err)
	}
	if skill.Name != "sql-injection" {
		t.Errorf("name = %q, want sql-injection", skill.Name)
	}
	if skill.Category != "exploit" {
		t.Errorf("category = %q, want exploit", skill.Category)
	}
	if skill.Difficulty != "medium" {
		t.Errorf("difficulty = %q, want medium", skill.Difficulty)
	}
	if skill.Body == "" {
		t.Error("body is empty")
	}
}

func TestScanSkills(t *testing.T) {
	dir := filepath.Join(testdataDir(), "skills")
	skills, err := ScanSkills(dir)
	if err != nil {
		t.Fatalf("ScanSkills: %v", err)
	}
	if len(skills) == 0 {
		t.Fatal("expected at least 1 skill")
	}
}

func TestScanDicts(t *testing.T) {
	dir := filepath.Join(testdataDir(), "Dic")
	dicts, err := ScanDicts(dir)
	if err != nil {
		t.Fatalf("ScanDicts: %v", err)
	}
	if len(dicts) == 0 {
		t.Fatal("expected at least 1 dict")
	}
	if dicts[0].LineCount == 0 {
		t.Error("line count is 0")
	}
}

func TestScanPayloads(t *testing.T) {
	dir := filepath.Join(testdataDir(), "Payload")
	payloads, err := ScanPayloads(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) == 0 {
		t.Fatal("expected at least 1 payload")
	}
}

func TestParseToolYAML(t *testing.T) {
	path := filepath.Join(testdataDir(), "Tools", "ext_nmap.yaml")
	tool, err := ParseToolYAML(path)
	if err != nil {
		t.Fatal(err)
	}
	if tool.ID != "ext_nmap" {
		t.Errorf("id = %q, want ext_nmap", tool.ID)
	}
	if tool.Category != "scan" {
		t.Errorf("category = %q, want scan", tool.Category)
	}
}

func TestReadFileLines(t *testing.T) {
	path := filepath.Join(testdataDir(), "Dic", "Auth", "password", "Top10.txt")
	content, total, err := ReadFileLines(path, 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	if total != 10 {
		t.Errorf("total = %d, want 10", total)
	}
	lines := len(splitLines(content))
	if lines != 5 {
		t.Errorf("returned lines = %d, want 5", lines)
	}
}

func TestParseDirMeta(t *testing.T) {
	dir := filepath.Join(testdataDir(), "Dic", "Auth", "password")
	meta, err := ParseDirMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if meta == nil {
		t.Fatal("expected meta")
	}
	if meta.Category != "auth" {
		t.Errorf("category = %q", meta.Category)
	}
	if len(meta.Files) == 0 {
		t.Fatal("expected files")
	}
	if meta.Files[0].Name != "Top10.txt" {
		t.Errorf("file = %q", meta.Files[0].Name)
	}
}

func TestScanTools_Recursive(t *testing.T) {
	dir := filepath.Join(testdataDir(), "Tools")
	tools, err := ScanTools(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, tool := range tools {
		found[tool.ID] = true
	}
	if !found["ext_nmap"] {
		t.Error("expected ext_nmap from top-level")
	}
	if !found["masscan"] {
		t.Error("expected masscan from scan/ subdirectory")
	}
}

func TestParseDirMeta_NoFile(t *testing.T) {
	meta, err := ParseDirMeta(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if meta != nil {
		t.Error("expected nil")
	}
}

func TestScanDicts_MetaYaml(t *testing.T) {
	dir := filepath.Join(testdataDir(), "Dic")
	dicts, err := ScanDicts(dir)
	if err != nil {
		t.Fatal(err)
	}
	var top10 *DictEntry
	for i := range dicts {
		if strings.HasSuffix(dicts[i].Path, "Top10.txt") {
			top10 = &dicts[i]
			break
		}
	}
	if top10 == nil {
		t.Fatal("Top10.txt not found")
	}
	if top10.Description == "" {
		t.Error("expected description")
	}
	if top10.Tags == "" {
		t.Error("expected tags")
	}
	if top10.Category != "auth" {
		t.Errorf("category = %q", top10.Category)
	}
}

func TestScanDicts_SkipsMetaFiles(t *testing.T) {
	dir := filepath.Join(testdataDir(), "Dic")
	dicts, err := ScanDicts(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dicts {
		base := filepath.Base(d.Path)
		if base == "_meta.yaml" || base == ".gitkeep" || base == ".DS_Store" || strings.EqualFold(base, "readme.md") {
			t.Errorf("should skip %s", d.Path)
		}
	}
}
