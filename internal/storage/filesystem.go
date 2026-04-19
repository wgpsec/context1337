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
	Body        string
	FilePath    string
}

type DictEntry struct {
	Path      string
	Type      string
	LineCount int
	SizeBytes int64
	FilePath  string
}

type PayloadEntry struct {
	Path      string
	Type      string
	LineCount int
	SizeBytes int64
	FilePath  string
}

type ToolData struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Homepage    string `yaml:"homepage"`
	Category    string `yaml:"category"`
	Binary      string `yaml:"binary"`
	FilePath    string `yaml:"-"`
	RawYAML     string `yaml:"-"`
}

type skillFrontmatter struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Metadata    struct {
		Tags       string `yaml:"tags"`
		Category   string `yaml:"category"`
		Difficulty string `yaml:"difficulty"`
	} `yaml:"metadata"`
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
		Body:        strings.TrimSpace(body),
		FilePath:    path,
	}, nil
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
		skills = append(skills, *skill)
		return nil
	})
	return skills, err
}

func ScanDicts(dir string) ([]DictEntry, error) {
	var dicts []DictEntry
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		relPath, _ := filepath.Rel(dir, path)
		parts := strings.SplitN(relPath, string(filepath.Separator), 2)
		dictType := ""
		if len(parts) > 0 {
			dictType = parts[0]
		}
		lc, _ := countLines(path)
		dicts = append(dicts, DictEntry{
			Path:      relPath,
			Type:      dictType,
			LineCount: lc,
			SizeBytes: info.Size(),
			FilePath:  path,
		})
		return nil
	})
	return dicts, err
}

func ScanPayloads(dir string) ([]PayloadEntry, error) {
	var payloads []PayloadEntry
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		relPath, _ := filepath.Rel(dir, path)
		parts := strings.SplitN(relPath, string(filepath.Separator), 2)
		pType := ""
		if len(parts) > 0 {
			pType = parts[0]
		}
		lc, _ := countLines(path)
		payloads = append(payloads, PayloadEntry{
			Path:      relPath,
			Type:      pType,
			LineCount: lc,
			SizeBytes: info.Size(),
			FilePath:  path,
		})
		return nil
	})
	return payloads, err
}

func ParseToolYAML(path string) (*ToolData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tool ToolData
	if err := yaml.Unmarshal(data, &tool); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	tool.FilePath = path
	tool.RawYAML = string(data)
	return &tool, nil
}

func ScanTools(dir string) ([]ToolData, error) {
	var tools []ToolData
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		tool, err := ParseToolYAML(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		tools = append(tools, *tool)
	}
	return tools, nil
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
