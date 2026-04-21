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

type SearchToolsInput struct {
	Query    string `json:"query"              jsonschema:"Search keyword e.g. nmap, port scan, dns"`
	Function string `json:"function,omitempty" jsonschema:"Filter: scan|fuzz|osint|poc|brute|postexploit"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results (default 10)"`
}

func (s *Service) SearchTools(ctx context.Context, in SearchToolsInput) ([]ToolSummary, error) {
	if in.Limit <= 0 {
		in.Limit = 10
	}
	results, err := search.Search(s.DB, search.SearchQuery{
		Query: in.Query, Type: "tool", Category: in.Function, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]ToolSummary, len(results))
	for i, r := range results {
		var binary string
		if r.Metadata != "" {
			var meta map[string]string
			json.Unmarshal([]byte(r.Metadata), &meta)
			binary = meta["binary"]
		}
		out[i] = ToolSummary{
			Name: r.Name, Description: r.Description,
			Function: r.Category, Binary: binary,
		}
	}
	return out, nil
}

type ListToolsInput struct {
	Function string `json:"function,omitempty" jsonschema:"Filter: scan|fuzz|osint|poc|brute|postexploit"`
}

type ToolSummary struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Function    string `json:"function"`
	Binary      string `json:"binary,omitempty"`
}

func (s *Service) ListTools(ctx context.Context, in ListToolsInput) ([]ToolSummary, error) {
	resources, err := search.ListByTypeCompat(s.DB, "tool", in.Function, 100)
	if err != nil {
		return nil, err
	}
	out := make([]ToolSummary, len(resources))
	for i, r := range resources {
		var binary string
		if r.Metadata != "" {
			var meta map[string]string
			json.Unmarshal([]byte(r.Metadata), &meta)
			binary = meta["binary"]
		}
		out[i] = ToolSummary{
			Name: r.Name, Description: r.Description,
			Function: r.Category, Binary: binary,
		}
	}
	return out, nil
}

type GetToolInput struct {
	Name string `json:"name" jsonschema:"Tool name e.g. dnsx, nmap, sqlmap"`
}

type ToolDetail struct {
	Name   string `json:"name"`
	Config string `json:"config"`
}

func (s *Service) GetTool(ctx context.Context, in GetToolInput) (*ToolDetail, error) {
	r, err := search.GetByName(s.DB, "tool", in.Name)
	if err != nil {
		return nil, err
	}
	// Fallback: search by keyword
	if r == nil {
		results, err := search.Search(s.DB, search.SearchQuery{
			Query: in.Name, Type: "tool", Limit: 1,
		})
		if err == nil && len(results) > 0 {
			r = &results[0].Resource
		}
	}
	if r == nil {
		return nil, fmt.Errorf("tool %q not found", in.Name)
	}
	// Resolve file path: try DB path first, fall back to DataDir/Tools/
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
	return &ToolDetail{Name: in.Name, Config: string(config)}, nil
}
