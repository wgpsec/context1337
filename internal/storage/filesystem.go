package storage

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type SkillData struct {
	Name        string
	Description string
	Tags        string
	Category    string
	Difficulty  string
	Mitre       string
	Body        string
	FilePath    string
}

type DictEntry struct {
	Path        string
	Type        string
	Category    string
	Description string
	Tags        string
	LineCount   int
	SizeBytes   int64
	FilePath    string
}

type PayloadEntry struct {
	Path        string
	Type        string
	Category    string
	Description string
	Tags        string
	LineCount   int
	SizeBytes   int64
	FilePath    string
}

type VulnData struct {
	ID              string
	Title           string
	Description     string
	Product         string
	Vendor          string
	VersionAffected string
	Severity        string
	Tags            string
	Fingerprint     string
	Category        string
	Body            string
	FilePath        string
}

type vulnFrontmatter struct {
	ID              string   `yaml:"id"`
	Title           string   `yaml:"title"`
	Description     string   `yaml:"description"`
	Product         string   `yaml:"product"`
	Vendor          string   `yaml:"vendor"`
	VersionAffected string   `yaml:"version_affected"`
	Severity        string   `yaml:"severity"`
	Tags            []string `yaml:"tags"`
	Fingerprint     string   `yaml:"fingerprint"`
}

type skillFrontmatter struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Metadata    struct {
		Tags        string `yaml:"tags"`
		Category    string `yaml:"category"`
		Difficulty  string `yaml:"difficulty"`
		MitreAttack string `yaml:"mitre_attack"`
	} `yaml:"metadata"`
}

type DirMeta struct {
	Category    string     `yaml:"category"`
	Subcategory string     `yaml:"subcategory"`
	Description string     `yaml:"description"`
	Tags        string     `yaml:"tags"`
	Files       []FileMeta `yaml:"files"`
}

type FileMeta struct {
	Name        string `yaml:"name"`
	Lines       int    `yaml:"lines"`
	Description string `yaml:"description"`
	Usage       string `yaml:"usage"`
	Tags        string `yaml:"tags"`
}

// ReferenceFile represents a single reference file from a skill's references/ directory.
type ReferenceFile struct {
	Name    string
	Content string
}

// ReadReferences reads all .md files from skillDir/references/, sorted by name.
// Returns empty slice (not error) if references/ doesn't exist.
func ReadReferences(skillDir string) ([]ReferenceFile, error) {
	refDir := filepath.Join(skillDir, "references")
	entries, err := os.ReadDir(refDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var refs []ReferenceFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(refDir, e.Name()))
		if err != nil {
			continue
		}
		refs = append(refs, ReferenceFile{Name: e.Name(), Content: string(data)})
	}
	return refs, nil
}

func ParseDirMeta(dir string) (*DirMeta, error) {
	path := filepath.Join(dir, "_meta.yaml")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var meta DirMeta
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &meta, nil
}

var skipFiles = map[string]bool{
	"_meta.yaml": true, ".gitkeep": true, ".DS_Store": true,
}

func isSkipFile(name string) bool {
	if skipFiles[name] {
		return true
	}
	return strings.EqualFold(name, "readme.md")
}

func ParseSkillMD(path string) (*SkillData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	content := string(data)
	fm, body, err := splitFrontmatter(content)
	if err != nil {
		return nil, fmt.Errorf("parse frontmatter in %s: %w", path, err)
	}
	var meta skillFrontmatter
	if err := yaml.Unmarshal([]byte(fm), &meta); err != nil {
		return nil, fmt.Errorf("unmarshal frontmatter in %s: %w", path, err)
	}
	return &SkillData{
		Name:        meta.Name,
		Description: meta.Description,
		Tags:        meta.Metadata.Tags,
		Category:    meta.Metadata.Category,
		Difficulty:  meta.Metadata.Difficulty,
		Mitre:       meta.Metadata.MitreAttack,
		Body:        strings.TrimSpace(body),
		FilePath:    path,
	}, nil
}

func ParseVulnMD(path string) (*VulnData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	content := string(data)
	fm, body, err := splitFrontmatter(content)
	if err != nil {
		return nil, nil // skip unparseable
	}
	if fm == "" {
		return nil, nil
	}
	var meta vulnFrontmatter
	if err := yaml.Unmarshal([]byte(fm), &meta); err != nil {
		return nil, nil // skip unparseable
	}
	if meta.ID == "" {
		return nil, nil
	}

	desc := meta.Description
	trimmedBody := strings.TrimSpace(body)
	// Fallback: extract first paragraph after "## 漏洞描述" heading if description is empty
	if desc == "" {
		desc = extractVulnDesc(trimmedBody, meta.Title)
	}

	return &VulnData{
		ID:              meta.ID,
		Title:           meta.Title,
		Description:     desc,
		Product:         meta.Product,
		Vendor:          meta.Vendor,
		VersionAffected: meta.VersionAffected,
		Severity:        strings.ToUpper(meta.Severity),
		Tags:            strings.Join(meta.Tags, ","),
		Fingerprint:     meta.Fingerprint,
		Body:            trimmedBody,
		FilePath:        path,
	}, nil
}

// extractVulnDesc extracts a description from vuln body content.
// Looks for "## 漏洞描述" section first, then falls back to title.
func extractVulnDesc(body, title string) string {
	// Try to find "## 漏洞描述" section
	markers := []string{"## 漏洞描述", "## 漏洞概述", "## 简介", "## 概述"}
	for _, marker := range markers {
		if idx := strings.Index(body, marker); idx >= 0 {
			after := body[idx+len(marker):]
			after = strings.TrimLeft(after, " \t\r\n")
			// Take first paragraph (up to double newline or next heading)
			end := len(after)
			if i := strings.Index(after, "\n\n"); i >= 0 {
				end = i
			}
			if i := strings.Index(after, "\n#"); i >= 0 && i < end {
				end = i
			}
			para := strings.TrimSpace(after[:end])
			if para != "" {
				if len([]rune(para)) > 200 {
					para = string([]rune(para)[:200]) + "..."
				}
				return para
			}
		}
	}
	// Fallback to title
	return title
}

func splitFrontmatter(content string) (string, string, error) {
	if !strings.HasPrefix(content, "---") {
		return "", content, nil
	}
	rest := content[3:]
	idx := strings.Index(rest, "\n---")
	if idx < 0 {
		return "", content, fmt.Errorf("unclosed frontmatter")
	}
	fm := strings.TrimSpace(rest[:idx])
	body := rest[idx+4:]
	return fm, body, nil
}

func ScanSkills(dir string) ([]SkillData, error) {
	var skills []SkillData
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || info.Name() != "SKILL.md" {
			return nil
		}
		skill, err := ParseSkillMD(path)
		if err != nil {
			return err
		}
		// Append references content to body for FTS5 indexing
		skillDir := filepath.Dir(path)
		refs, _ := ReadReferences(skillDir)
		if len(refs) > 0 {
			var parts []string
			parts = append(parts, skill.Body)
			for _, ref := range refs {
				parts = append(parts, "\n\n---\n## [ref] "+ref.Name+"\n"+ref.Content)
			}
			skill.Body = strings.Join(parts, "")
		}
		skills = append(skills, *skill)
		return nil
	})
	return skills, err
}

func ScanDicts(dir string) ([]DictEntry, error) {
	var dicts []DictEntry
	metaCache := map[string]*DirMeta{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if isSkipFile(info.Name()) {
			return nil
		}
		relPath, _ := filepath.Rel(dir, path)
		parts := strings.SplitN(relPath, string(filepath.Separator), 2)
		dictType := ""
		if len(parts) > 0 {
			dictType = parts[0]
		}

		parentDir := filepath.Dir(path)
		meta, cached := metaCache[parentDir]
		if !cached {
			meta, _ = ParseDirMeta(parentDir)
			metaCache[parentDir] = meta
		}

		lc, _ := countLines(path)
		entry := DictEntry{
			Path:      relPath,
			Type:      dictType,
			Category:  dictType,
			LineCount: lc,
			SizeBytes: info.Size(),
			FilePath:  path,
		}

		if meta != nil {
			if meta.Category != "" {
				entry.Category = meta.Category
			}
			entry.Description = meta.Description
			entry.Tags = meta.Tags

			for _, fm := range meta.Files {
				if fm.Name == info.Name() {
					if fm.Description != "" {
						entry.Description = fm.Description
					}
					if fm.Tags != "" {
						if entry.Tags != "" {
							entry.Tags = entry.Tags + "," + fm.Tags
						} else {
							entry.Tags = fm.Tags
						}
					}
					break
				}
			}
		}

		dicts = append(dicts, entry)
		return nil
	})
	return dicts, err
}

func ScanPayloads(dir string) ([]PayloadEntry, error) {
	var payloads []PayloadEntry
	metaCache := map[string]*DirMeta{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if isSkipFile(info.Name()) {
			return nil
		}
		relPath, _ := filepath.Rel(dir, path)
		parts := strings.SplitN(relPath, string(filepath.Separator), 2)
		pType := ""
		if len(parts) > 0 {
			pType = parts[0]
		}

		parentDir := filepath.Dir(path)
		meta, cached := metaCache[parentDir]
		if !cached {
			meta, _ = ParseDirMeta(parentDir)
			metaCache[parentDir] = meta
		}

		lc, _ := countLines(path)
		entry := PayloadEntry{
			Path:      relPath,
			Type:      pType,
			Category:  pType,
			LineCount: lc,
			SizeBytes: info.Size(),
			FilePath:  path,
		}

		if meta != nil {
			if meta.Category != "" {
				entry.Category = meta.Category
			}
			entry.Description = meta.Description
			entry.Tags = meta.Tags

			for _, fm := range meta.Files {
				if fm.Name == info.Name() {
					if fm.Description != "" {
						entry.Description = fm.Description
					}
					if fm.Tags != "" {
						if entry.Tags != "" {
							entry.Tags = entry.Tags + "," + fm.Tags
						} else {
							entry.Tags = fm.Tags
						}
					}
					break
				}
			}
		}

		payloads = append(payloads, entry)
		return nil
	})
	return payloads, err
}

func ScanVulns(dir string) ([]VulnData, error) {
	var vulns []VulnData
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(d.Name(), ".md") || isSkipFile(d.Name()) {
			return nil
		}
		vuln, err := ParseVulnMD(path)
		if err != nil || vuln == nil {
			return nil // skip unparseable or nil
		}
		rel, _ := filepath.Rel(dir, path)
		parts := strings.SplitN(rel, string(filepath.Separator), 2)
		if len(parts) > 1 {
			vuln.Category = parts[0]
		}
		vulns = append(vulns, *vuln)
		return nil
	})
	return vulns, err
}

func ReadFileLines(path string, offset, limit int) (string, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var lines []string
	total := 0
	for scanner.Scan() {
		total++
		if offset > 0 && total <= offset {
			continue
		}
		if limit > 0 && len(lines) >= limit {
			continue
		}
		lines = append(lines, scanner.Text())
	}
	return strings.Join(lines, "\n"), total, scanner.Err()
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
	}
	return count, scanner.Err()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
