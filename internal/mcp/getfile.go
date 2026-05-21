package mcp

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/wgpsec/context1337/internal/search"
	"github.com/wgpsec/context1337/internal/storage"
)

// --- get_file ---

type GetFileInput struct {
	ID     string `json:"id,omitempty"     jsonschema:"Stable resource ID from search results"`
	Path   string `json:"path,omitempty"   jsonschema:"Relative file path from search results (e.g. Auth/password/Top100.txt)"`
	Type   string `json:"type,omitempty"   jsonschema:"Resource type: dict|payload"`
	Offset int    `json:"offset,omitempty" jsonschema:"Line offset for pagination (default 0)"`
	Limit  int    `json:"limit,omitempty"  jsonschema:"Max lines to return (default 200)"`
}

type GetFileResult struct {
	ID            string `json:"id,omitempty"`
	Path          string `json:"path"`
	Type          string `json:"type"`
	TotalLines    int    `json:"total_lines"`
	ReturnedLines int    `json:"returned_lines"`
	Content       string `json:"content"`
}

func (s *Service) GetFile(ctx context.Context, in GetFileInput) (*GetFileResult, error) {
	id, typ, path, absPath, err := s.resolveFileResource(in)
	if err != nil {
		return nil, err
	}
	if in.Limit <= 0 {
		in.Limit = 200
	}

	content, total, err := storage.ReadFileLines(absPath, in.Offset, in.Limit)
	if err != nil {
		return nil, fmt.Errorf("read %s %q: %w", typ, path, err)
	}
	returned := total - in.Offset
	if in.Limit > 0 && returned > in.Limit {
		returned = in.Limit
	}
	return &GetFileResult{
		ID: id, Path: path, Type: typ,
		TotalLines: total, ReturnedLines: returned, Content: content,
	}, nil
}

func fileBaseDir(typ string) (string, error) {
	switch typ {
	case "dict":
		return "Dic", nil
	case "payload":
		return "Payload", nil
	default:
		return "", fmt.Errorf("type must be dict or payload (use get for skill/tool)")
	}
}

func (s *Service) resolveFileResource(in GetFileInput) (id, typ, path, absPath string, err error) {
	if in.ID == "" {
		baseDir, err := fileBaseDir(in.Type)
		if err != nil {
			return "", "", "", "", err
		}
		clean, err := cleanFileResourceName(in.Path)
		if err != nil {
			return "", "", "", "", err
		}
		return "", in.Type, clean, filepath.Join(s.DataDir, baseDir, clean), nil
	}

	r, err := search.GetByStableID(s.DB, in.ID)
	if err != nil {
		return "", "", "", "", err
	}
	if r == nil {
		return "", "", "", "", fmt.Errorf("resource id %q not found", in.ID)
	}
	if r.Type != "dict" && r.Type != "payload" {
		return "", "", "", "", fmt.Errorf("resource id %q resolves to type=%s; use get_security_detail for security details", in.ID, r.Type)
	}

	baseDir, err := fileBaseDir(r.Type)
	if err != nil {
		return "", "", "", "", err
	}
	clean, err := cleanFileResourceName(r.Name)
	if err != nil {
		return "", "", "", "", err
	}
	if in.Type != "" && in.Type != r.Type {
		return "", "", "", "", fmt.Errorf("type %q conflicts with resource id type %q", in.Type, r.Type)
	}
	if in.Path != "" {
		legacyClean, err := cleanFileResourceName(in.Path)
		if err != nil {
			return "", "", "", "", err
		}
		if legacyClean != clean {
			return "", "", "", "", fmt.Errorf("path %q conflicts with resource id path %q", in.Path, clean)
		}
	}

	root, err := s.fileSourceRoot(r.Source, baseDir, in.ID)
	if err != nil {
		return "", "", "", "", err
	}
	absPath = filepath.Join(root, clean)
	return search.StableID(*r), r.Type, clean, absPath, nil
}

func (s *Service) fileSourceRoot(source, baseDir, id string) (string, error) {
	switch source {
	case "builtin":
		return filepath.Join(s.DataDir, baseDir), nil
	case "team":
		return filepath.Join(s.DataDir, "team", baseDir), nil
	default:
		return "", fmt.Errorf("resource id %q resolves to unsupported file source %q", id, source)
	}
}

func cleanFileResourceName(name string) (string, error) {
	clean := filepath.Clean(name)
	if filepath.IsAbs(clean) || clean == "." || hasParentPathComponent(clean) {
		return "", fmt.Errorf("invalid path")
	}
	return clean, nil
}

func hasParentPathComponent(path string) bool {
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		if part == ".." {
			return true
		}
	}
	return false
}
