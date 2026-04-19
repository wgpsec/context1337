package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

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
		out[i] = ToolSummary{
			ID: r.Name, Name: r.Description, Function: r.Category,
			Description: r.Description, Binary: binary,
		}
	}
	return out, nil
}

type GetToolInput struct {
	ID string `json:"id" jsonschema:"Tool ID e.g. nmap or sqlmap"`
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
	if r == nil {
		return nil, fmt.Errorf("tool %q not found", in.ID)
	}
	config, err := os.ReadFile(r.FilePath)
	if err != nil {
		return nil, fmt.Errorf("read tool config: %w", err)
	}
	return &ToolDetail{ID: in.ID, Config: string(config)}, nil
}
