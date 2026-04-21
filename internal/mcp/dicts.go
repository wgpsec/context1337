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
	Query    string `json:"query"              jsonschema:"Search keyword e.g. password, SSH, admin"`
	Category string `json:"category,omitempty" jsonschema:"Filter by category: auth|network|port|web|regular"`
	Offset   int    `json:"offset,omitempty"   jsonschema:"Pagination offset (default 0)"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results (default 20)"`
}

type DictSummary struct {
	Path        string `json:"path"`
	Category    string `json:"category"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source"`
}

type DictListResult struct {
	Total  int           `json:"total"`
	Offset int           `json:"offset"`
	Limit  int           `json:"limit"`
	Items  []DictSummary `json:"items"`
}

func (s *Service) SearchDicts(ctx context.Context, in SearchDictsInput) (*DictListResult, error) {
	if in.Limit <= 0 {
		in.Limit = 20
	}
	results, total, err := search.Search(s.DB, search.SearchQuery{
		Query: in.Query, Type: "dict", Category: in.Category,
		Offset: in.Offset, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	items := make([]DictSummary, len(results))
	for i, r := range results {
		items[i] = DictSummary{Path: r.Name, Category: r.Category, Description: r.Description, Source: r.Source}
	}
	return &DictListResult{Total: total, Offset: in.Offset, Limit: in.Limit, Items: items}, nil
}

type ListDictsInput struct {
	Category string `json:"category,omitempty" jsonschema:"Filter by category: auth|network|port|web|regular"`
	Offset   int    `json:"offset,omitempty"   jsonschema:"Pagination offset (default 0)"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results (default 50)"`
}

func (s *Service) ListDicts(ctx context.Context, in ListDictsInput) (*DictListResult, error) {
	if in.Limit <= 0 {
		in.Limit = 50
	}
	result, err := search.ListByType(s.DB, search.ListQuery{
		Type: "dict", Category: in.Category,
		Offset: in.Offset, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	items := make([]DictSummary, len(result.Items))
	for i, r := range result.Items {
		items[i] = DictSummary{Path: r.Name, Category: r.Category, Description: r.Description, Source: r.Source}
	}
	return &DictListResult{Total: result.Total, Offset: in.Offset, Limit: in.Limit, Items: items}, nil
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
