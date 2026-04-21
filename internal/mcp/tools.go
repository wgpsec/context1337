package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Esonhugh/context1337/internal/search"
)

// --- search_tools ---

type SearchToolsInput struct {
	Query    string `json:"query"              jsonschema:"Search keyword e.g. nmap, port scan, dns"`
	Category string `json:"category,omitempty" jsonschema:"Filter: scan|fuzz|osint|poc|brute|postexploit"`
	Offset   int    `json:"offset,omitempty"   jsonschema:"Pagination offset (default 0)"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results (default 10)"`
}

type ToolSummary struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Binary      string `json:"binary,omitempty"`
	Homepage    string `json:"homepage,omitempty"`
}

type ToolListResult struct {
	Total  int           `json:"total"`
	Offset int           `json:"offset"`
	Limit  int           `json:"limit"`
	Items  []ToolSummary `json:"items"`
}

func extractToolMeta(metadata string) (binary, homepage string) {
	if metadata == "" {
		return
	}
	var meta map[string]string
	json.Unmarshal([]byte(metadata), &meta)
	return meta["binary"], meta["homepage"]
}

func (s *Service) SearchTools(ctx context.Context, in SearchToolsInput) (*ToolListResult, error) {
	if in.Limit <= 0 {
		in.Limit = 10
	}
	results, total, err := search.Search(s.DB, search.SearchQuery{
		Query: in.Query, Type: "tool", Category: in.Category,
		Offset: in.Offset, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	items := make([]ToolSummary, len(results))
	for i, r := range results {
		binary, homepage := extractToolMeta(r.Metadata)
		items[i] = ToolSummary{
			Name: r.Name, Description: r.Description,
			Category: r.Category, Binary: binary, Homepage: homepage,
		}
	}
	return &ToolListResult{Total: total, Offset: in.Offset, Limit: in.Limit, Items: items}, nil
}

// --- list_tools ---

type ListToolsInput struct {
	Category string `json:"category,omitempty" jsonschema:"Filter: scan|fuzz|osint|poc|brute|postexploit"`
	Offset   int    `json:"offset,omitempty"   jsonschema:"Pagination offset (default 0)"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results (default 50)"`
}

func (s *Service) ListTools(ctx context.Context, in ListToolsInput) (*ToolListResult, error) {
	if in.Limit <= 0 {
		in.Limit = 50
	}
	result, err := search.ListByType(s.DB, search.ListQuery{
		Type: "tool", Category: in.Category,
		Offset: in.Offset, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	items := make([]ToolSummary, len(result.Items))
	for i, r := range result.Items {
		binary, homepage := extractToolMeta(r.Metadata)
		items[i] = ToolSummary{
			Name: r.Name, Description: r.Description,
			Category: r.Category, Binary: binary, Homepage: homepage,
		}
	}
	return &ToolListResult{Total: result.Total, Offset: in.Offset, Limit: in.Limit, Items: items}, nil
}

// --- get_tool ---

type GetToolInput struct {
	Name string `json:"name" jsonschema:"Tool name e.g. dnsx, nmap, sqlmap"`
}

type ToolDetail struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Binary   string `json:"binary,omitempty"`
	Homepage string `json:"homepage,omitempty"`
	Config   string `json:"config"`
}

func (s *Service) GetTool(ctx context.Context, in GetToolInput) (*ToolDetail, error) {
	r, err := search.GetByName(s.DB, "tool", in.Name)
	if err != nil {
		return nil, err
	}
	if r == nil {
		results, _, err := search.Search(s.DB, search.SearchQuery{
			Query: in.Name, Type: "tool", Limit: 1,
		})
		if err == nil && len(results) > 0 {
			r = &results[0].Resource
		}
	}
	if r == nil {
		return nil, fmt.Errorf("tool %q not found", in.Name)
	}

	readPath := r.FilePath
	if _, err := os.Stat(readPath); err != nil {
		clean := filepath.Clean(r.Name + ".yaml")
		if strings.Contains(clean, "..") {
			return nil, fmt.Errorf("invalid tool path")
		}
		readPath = filepath.Join(s.DataDir, "Tools", clean)
	}
	config, err := os.ReadFile(readPath)
	if err != nil {
		return nil, fmt.Errorf("read tool config: %w", err)
	}

	binary, homepage := extractToolMeta(r.Metadata)
	return &ToolDetail{
		Name: in.Name, Category: r.Category,
		Binary: binary, Homepage: homepage, Config: string(config),
	}, nil
}
