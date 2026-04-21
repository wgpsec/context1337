package mcp

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Esonhugh/context1337/internal/search"
	"github.com/Esonhugh/context1337/internal/storage"
)

// --- search_payload ---

type SearchPayloadInput struct {
	Query    string `json:"query"              jsonschema:"Search keyword"`
	Category string `json:"category,omitempty" jsonschema:"Filter: sqli|xss|ssrf|xxe|lfi|rce|cors"`
	Offset   int    `json:"offset,omitempty"   jsonschema:"Pagination offset (default 0)"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results (default 20)"`
}

type PayloadSummary struct {
	Path        string `json:"path"`
	Category    string `json:"category"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source"`
}

type PayloadListResult struct {
	Total  int              `json:"total"`
	Offset int              `json:"offset"`
	Limit  int              `json:"limit"`
	Items  []PayloadSummary `json:"items"`
}

func (s *Service) SearchPayload(ctx context.Context, in SearchPayloadInput) (*PayloadListResult, error) {
	if in.Limit <= 0 {
		in.Limit = 20
	}
	if in.Query != "" {
		results, total, err := search.Search(s.DB, search.SearchQuery{
			Query: in.Query, Type: "payload", Category: in.Category,
			Offset: in.Offset, Limit: in.Limit,
		})
		if err != nil {
			return nil, err
		}
		items := make([]PayloadSummary, len(results))
		for i, r := range results {
			items[i] = PayloadSummary{Path: r.Name, Category: r.Category, Description: r.Description, Source: r.Source}
		}
		return &PayloadListResult{Total: total, Offset: in.Offset, Limit: in.Limit, Items: items}, nil
	}
	// No query: fall back to list
	result, err := search.ListByType(s.DB, search.ListQuery{
		Type: "payload", Category: in.Category,
		Offset: in.Offset, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	items := make([]PayloadSummary, len(result.Items))
	for i, r := range result.Items {
		items[i] = PayloadSummary{Path: r.Name, Category: r.Category, Description: r.Description, Source: r.Source}
	}
	return &PayloadListResult{Total: result.Total, Offset: in.Offset, Limit: in.Limit, Items: items}, nil
}

// --- list_payloads ---

type ListPayloadsInput struct {
	Category string `json:"category,omitempty" jsonschema:"Filter: sqli|xss|ssrf|xxe|lfi|rce|cors"`
	Offset   int    `json:"offset,omitempty"   jsonschema:"Pagination offset (default 0)"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results (default 50)"`
}

func (s *Service) ListPayloads(ctx context.Context, in ListPayloadsInput) (*PayloadListResult, error) {
	if in.Limit <= 0 {
		in.Limit = 50
	}
	result, err := search.ListByType(s.DB, search.ListQuery{
		Type: "payload", Category: in.Category,
		Offset: in.Offset, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	items := make([]PayloadSummary, len(result.Items))
	for i, r := range result.Items {
		items[i] = PayloadSummary{Path: r.Name, Category: r.Category, Description: r.Description, Source: r.Source}
	}
	return &PayloadListResult{Total: result.Total, Offset: in.Offset, Limit: in.Limit, Items: items}, nil
}

// --- get_payload ---

type GetPayloadInput struct {
	Path   string `json:"path"             jsonschema:"Relative path e.g. XSS/events.txt"`
	Limit  int    `json:"limit,omitempty"  jsonschema:"Max lines to return (default 200, use with offset for pagination)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Line offset for pagination (default 0)"`
}

type PayloadContent struct {
	Path          string `json:"path"`
	TotalLines    int    `json:"total_lines"`
	ReturnedLines int    `json:"returned_lines"`
	Content       string `json:"content"`
}

func (s *Service) GetPayload(ctx context.Context, in GetPayloadInput) (*PayloadContent, error) {
	clean := filepath.Clean(in.Path)
	if strings.Contains(clean, "..") {
		return nil, fmt.Errorf("invalid path")
	}
	if in.Limit <= 0 {
		in.Limit = 200
	}
	absPath := filepath.Join(s.DataDir, "Payload", clean)
	content, total, err := storage.ReadFileLines(absPath, in.Offset, in.Limit)
	if err != nil {
		return nil, fmt.Errorf("read payload %q: %w", in.Path, err)
	}
	returned := total - in.Offset
	if in.Limit > 0 && returned > in.Limit {
		returned = in.Limit
	}
	return &PayloadContent{Path: in.Path, TotalLines: total, ReturnedLines: returned, Content: content}, nil
}
