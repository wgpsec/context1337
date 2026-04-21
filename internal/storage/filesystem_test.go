package storage

import (
	"os"
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

func TestReadReferences(t *testing.T) {
	skillDir := filepath.Join(testdataDir(), "skills", "exploit", "test-ref")
	refs, err := ReadReferences(skillDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("refs = %d, want 2", len(refs))
	}
	// Should be sorted by name
	if refs[0].Name != "advanced.md" {
		t.Errorf("first ref = %q, want advanced.md", refs[0].Name)
	}
	if refs[1].Name != "bypass.md" {
		t.Errorf("second ref = %q, want bypass.md", refs[1].Name)
	}
	if !strings.Contains(refs[0].Content, "Advanced Techniques") {
		t.Error("expected content in first ref")
	}
}

func TestReadReferences_NoDir(t *testing.T) {
	refs, err := ReadReferences(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("expected empty refs, got %d", len(refs))
	}
}

func TestScanSkills_ReferencesInBody(t *testing.T) {
	dir := filepath.Join(testdataDir(), "skills")
	skills, err := ScanSkills(dir)
	if err != nil {
		t.Fatal(err)
	}

	var refSkill *SkillData
	for i := range skills {
		if skills[i].Name == "test-ref" {
			refSkill = &skills[i]
			break
		}
	}
	if refSkill == nil {
		t.Fatal("test-ref skill not found")
	}
	if !strings.Contains(refSkill.Body, "Advanced Techniques") {
		t.Error("body should contain references content")
	}
	if !strings.Contains(refSkill.Body, "WAF bypass") {
		t.Error("body should contain bypass reference content")
	}
	if !strings.Contains(refSkill.Body, "Main body content") {
		t.Error("body should contain original SKILL.md body")
	}
}

func TestScanSkills_Mitre(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "exploit", "test-mitre")
	os.MkdirAll(skillDir, 0o755)
	os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(`---
name: test-mitre
description: Test MITRE mapping
metadata:
  tags: "test"
  category: "exploit"
  mitre_attack: "T1190,T1059"
---
Test body
`), 0o644)

	skills, err := ScanSkills(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(skills) == 0 {
		t.Fatal("expected at least 1 skill")
	}
	found := false
	for _, s := range skills {
		if s.Name == "test-mitre" {
			found = true
			if s.Mitre != "T1190,T1059" {
				t.Errorf("mitre = %q, want T1190,T1059", s.Mitre)
			}
		}
	}
	if !found {
		t.Error("test-mitre skill not found")
	}
}
