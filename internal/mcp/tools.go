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

type ListToolsInput struct {
	Function string `json:"function,omitempty" jsonschema:"Filter: scan|fuzz|osint|poc|brute|postexploit"`
}

type ToolSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Function    string `json:"function"`
	Description string `json:"description"`
	Binary      string `json:"binary,omitempty"`
}

func (s *Service) ListTools(ctx context.Context, in ListToolsInput) ([]ToolSummary, error) {
	resources, err := search.ListByType(s.DB, "tool", in.Function, 100)
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
		// r.Name stores tool ID (e.g. "nmap"), r.Body stores raw YAML with the real name
		toolName := r.Name
		if r.Description != "" {
			toolName = r.Description
		}
		out[i] = ToolSummary{
			ID: r.Name, Name: toolName, Function: r.Category,
			Description: r.Description, Binary: binary,
		}
	}
	return out, nil
}

type GetToolInput struct {
	ID string `json:"id" jsonschema:"Tool ID e.g. dnsx, nmap, sqlmap"`
}

type ToolDetail struct {
	ID     string `json:"id"`
	Config string `json:"config"`
}

func (s *Service) GetTool(ctx context.Context, in GetToolInput) (*ToolDetail, error) {
	r, err := search.GetByName(s.DB, "tool", in.ID)
	if err != nil {
		return nil, err
	}
	// Fallback: search by keyword
	if r == nil {
		results, err := search.Search(s.DB, search.SearchQuery{
			Query: in.ID, Type: "tool", Limit: 1,
		})
		if err == nil && len(results) > 0 {
			r = &results[0].Resource
		}
	}
	if r == nil {
		return nil, fmt.Errorf("tool %q not found", in.ID)
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
	return &ToolDetail{ID: in.ID, Config: string(config)}, nil
}
