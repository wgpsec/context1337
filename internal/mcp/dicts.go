package mcp

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Esonhugh/context1337/internal/search"
	"github.com/Esonhugh/context1337/internal/storage"
)

type SearchDictsInput struct {
	Query string `json:"query"             jsonschema:"Search keyword e.g. password, SSH, admin"`
	Type  string `json:"type,omitempty"    jsonschema:"Filter by type: auth|network|port|web|regular"`
	Limit int    `json:"limit,omitempty"   jsonschema:"Max results (default 20)"`
}

func (s *Service) SearchDicts(ctx context.Context, in SearchDictsInput) ([]DictSummary, error) {
	if in.Limit <= 0 {
		in.Limit = 20
	}
	results, err := search.Search(s.DB, search.SearchQuery{
		Query: in.Query, Type: "dict", Category: in.Type, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]DictSummary, len(results))
	for i, r := range results {
		out[i] = DictSummary{Path: r.Name, Type: r.Category, Description: r.Description, Source: r.Source}
	}
	return out, nil
}

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
	resources, err := search.ListByTypeCompat(s.DB, "dict", in.Type, 500)
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
	Limit  int    `json:"limit,omitempty"  jsonschema:"Max lines to return (default 200, use with offset for pagination)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Line offset for pagination (default 0)"`
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
	if in.Limit <= 0 {
		in.Limit = 200
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
