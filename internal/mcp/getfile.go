package mcp

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/wgpsec/context1337/internal/storage"
)

// --- get_file ---

type GetFileInput struct {
	Path   string `json:"path"             jsonschema:"Relative file path from search results (e.g. Auth/password/Top100.txt)"`
	Type   string `json:"type"             jsonschema:"Resource type: dict|payload"`
	Offset int    `json:"offset,omitempty" jsonschema:"Line offset for pagination (default 0)"`
	Limit  int    `json:"limit,omitempty"  jsonschema:"Max lines to return (default 200)"`
}

type GetFileResult struct {
	Path          string `json:"path"`
	Type          string `json:"type"`
	TotalLines    int    `json:"total_lines"`
	ReturnedLines int    `json:"returned_lines"`
	Content       string `json:"content"`
}

func (s *Service) GetFile(ctx context.Context, in GetFileInput) (*GetFileResult, error) {
	var baseDir string
	switch in.Type {
	case "dict":
		baseDir = "Dic"
	case "payload":
		baseDir = "Payload"
	default:
		return nil, fmt.Errorf("type must be dict or payload (use get for skill/tool)")
	}

	clean := filepath.Clean(in.Path)
	if strings.Contains(clean, "..") {
		return nil, fmt.Errorf("invalid path")
	}
	if in.Limit <= 0 {
		in.Limit = 200
	}

	absPath := filepath.Join(s.DataDir, baseDir, clean)
	content, total, err := storage.ReadFileLines(absPath, in.Offset, in.Limit)
	if err != nil {
		return nil, fmt.Errorf("read %s %q: %w", in.Type, in.Path, err)
	}
	returned := total - in.Offset
	if in.Limit > 0 && returned > in.Limit {
		returned = in.Limit
	}
	return &GetFileResult{
		Path: in.Path, Type: in.Type,
		TotalLines: total, ReturnedLines: returned, Content: content,
	}, nil
}
