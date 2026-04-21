package mcp

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Esonhugh/context1337/internal/search"
	"github.com/Esonhugh/context1337/internal/storage"
)

type SearchPayloadInput struct {
	Query string `json:"query,omitempty" jsonschema:"Search keyword"`
	Type  string `json:"type,omitempty"  jsonschema:"Filter: sqli|xss|ssrf|xxe|lfi|rce|cors"`
}

type PayloadSummary struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

func (s *Service) SearchPayload(ctx context.Context, in SearchPayloadInput) ([]PayloadSummary, error) {
	if in.Query != "" {
		results, _, err := search.Search(s.DB, search.SearchQuery{
			Query: in.Query, Type: "payload", Category: in.Type, Limit: 50,
		})
		if err != nil {
			return nil, err
		}
		out := make([]PayloadSummary, len(results))
		for i, r := range results {
			out[i] = PayloadSummary{Path: r.Name, Type: r.Category, Description: r.Description}
		}
		return out, nil
	}
	resources, err := search.ListByTypeCompat(s.DB, "payload", in.Type, 100)
	if err != nil {
		return nil, err
	}
	out := make([]PayloadSummary, len(resources))
	for i, r := range resources {
		out[i] = PayloadSummary{Path: r.Name, Type: r.Category, Description: r.Description}
	}
	return out, nil
}

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
