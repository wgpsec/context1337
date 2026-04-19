package mcp

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Esonhugh/context1337/internal/search"
	"github.com/Esonhugh/context1337/internal/storage"
)

type ListDictsInput struct {
	Type string `json:"type,omitempty" jsonschema:"Filter by type: auth|network|port|web|regular"`
}

type DictSummary struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source"`
}

func (s *Service) ListDicts(ctx context.Context, in ListDictsInput) ([]DictSummary, error) {
	resources, err := search.ListByType(s.DB, "dict", in.Type, 500)
	if err != nil {
		return nil, err
	}
	out := make([]DictSummary, len(resources))
	for i, r := range resources {
		out[i] = DictSummary{Path: r.Name, Type: r.Category, Description: r.Description, Source: r.Source}
	}
	return out, nil
}

type GetDictInput struct {
	Path   string `json:"path"             jsonschema:"Relative path e.g. Auth/password/Top100.txt"`
	Limit  int    `json:"limit,omitempty"  jsonschema:"Max lines (default 0=all)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Line offset for pagination"`
}

type DictContent struct {
	Path          string `json:"path"`
	TotalLines    int    `json:"total_lines"`
	ReturnedLines int    `json:"returned_lines"`
	Content       string `json:"content"`
}

func (s *Service) GetDict(ctx context.Context, in GetDictInput) (*DictContent, error) {
	clean := filepath.Clean(in.Path)
	if strings.Contains(clean, "..") {
		return nil, fmt.Errorf("invalid path")
	}
	absPath := filepath.Join(s.DataDir, "Dic", clean)
	content, total, err := storage.ReadFileLines(absPath, in.Offset, in.Limit)
	if err != nil {
		return nil, fmt.Errorf("read dict %q: %w", in.Path, err)
	}
	returned := total - in.Offset
	if in.Limit > 0 && returned > in.Limit {
		returned = in.Limit
	}
	return &DictContent{Path: in.Path, TotalLines: total, ReturnedLines: returned, Content: content}, nil
}
