package mcp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Esonhugh/context1337/internal/search"
	"github.com/Esonhugh/context1337/internal/storage"
)

// --- search ---

type SearchInput struct {
	Query      string `json:"query,omitempty"      jsonschema:"Search keywords (omit to list all)"`
	Type       string `json:"type,omitempty"       jsonschema:"Filter by type: skill|dict|payload|tool (omit to search all)"`
	Category   string `json:"category,omitempty"   jsonschema:"Filter by category"`
	Difficulty string `json:"difficulty,omitempty" jsonschema:"Filter by difficulty (skill only): easy|medium|hard"`
	Offset     int    `json:"offset,omitempty"     jsonschema:"Pagination offset (default 0)"`
	Limit      int    `json:"limit,omitempty"      jsonschema:"Max results (default 20)"`
}

type ResourceSummary struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Source      string `json:"source"`
	Tags        string `json:"tags,omitempty"`
	Difficulty  string `json:"difficulty,omitempty"`
	Binary      string `json:"binary,omitempty"`
	Homepage    string `json:"homepage,omitempty"`
}

type SearchResult struct {
	Total  int               `json:"total"`
	Offset int               `json:"offset"`
	Limit  int               `json:"limit"`
	Items  []ResourceSummary `json:"items"`
}

func resourceToSummary(r search.Resource) ResourceSummary {
	s := ResourceSummary{
		Name: r.Name, Type: r.Type, Description: r.Description,
		Category: r.Category, Source: r.Source,
		Tags: r.Tags, Difficulty: r.Difficulty,
	}
	if r.Type == "tool" {
		s.Binary, s.Homepage = extractToolMeta(r.Metadata)
	}
	return s
}

func (s *Service) Search(ctx context.Context, in SearchInput) (*SearchResult, error) {
	if in.Limit <= 0 {
		in.Limit = 20
	}

	// Non-empty query -> FTS5 search
	if in.Query != "" {
		results, total, err := search.Search(s.DB, search.SearchQuery{
			Query: in.Query, Type: in.Type, Category: in.Category,
			Difficulty: in.Difficulty, Offset: in.Offset, Limit: in.Limit,
		})
		if err != nil {
			return nil, err
		}
		items := make([]ResourceSummary, len(results))
		for i, r := range results {
			items[i] = resourceToSummary(r.Resource)
		}
		return &SearchResult{Total: total, Offset: in.Offset, Limit: in.Limit, Items: items}, nil
	}

	// Empty query -> list
	result, err := search.ListByType(s.DB, search.ListQuery{
		Type: in.Type, Category: in.Category,
		Difficulty: in.Difficulty, Offset: in.Offset, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	items := make([]ResourceSummary, len(result.Items))
	for i, r := range result.Items {
		items[i] = resourceToSummary(r)
	}
	return &SearchResult{Total: result.Total, Offset: in.Offset, Limit: in.Limit, Items: items}, nil
}

// --- get ---

type GetInput struct {
	Name  string `json:"name"            jsonschema:"Resource name (from search results)"`
	Type  string `json:"type"            jsonschema:"Resource type: skill|tool"`
	Depth string `json:"depth,omitempty" jsonschema:"Loading depth (skill only): metadata|summary|full (default summary). full includes references."`
}

type GetResult struct {
	Name        string           `json:"name"`
	Type        string           `json:"type"`
	Description string           `json:"description"`
	Category    string           `json:"category"`
	Source      string           `json:"source"`
	Tags        string           `json:"tags,omitempty"`
	Difficulty  string           `json:"difficulty,omitempty"`
	Body        string           `json:"body,omitempty"`
	References  []SkillReference `json:"references,omitempty"`
	Binary      string           `json:"binary,omitempty"`
	Homepage    string           `json:"homepage,omitempty"`
	Config      string           `json:"config,omitempty"`
}

func (s *Service) Get(ctx context.Context, in GetInput) (*GetResult, error) {
	if in.Type != "skill" && in.Type != "tool" {
		return nil, fmt.Errorf("type must be skill or tool (use get_file for dict/payload)")
	}

	r, err := search.GetByName(s.DB, in.Type, in.Name)
	if err != nil {
		return nil, err
	}
	if r == nil {
		results, _, err := search.Search(s.DB, search.SearchQuery{
			Query: in.Name, Type: in.Type, Limit: 1,
		})
		if err == nil && len(results) > 0 {
			r = &results[0].Resource
		}
	}
	if r == nil {
		return nil, fmt.Errorf("%s %q not found", in.Type, in.Name)
	}

	result := &GetResult{
		Name: r.Name, Type: r.Type, Description: r.Description,
		Category: r.Category, Source: r.Source,
		Tags: r.Tags, Difficulty: r.Difficulty,
	}

	switch in.Type {
	case "skill":
		if in.Depth == "" {
			in.Depth = "summary"
		}
		switch in.Depth {
		case "metadata":
			// No body
		case "summary":
			result.Body = r.Body
		case "full":
			result.Body = r.Body
			skillDir := filepath.Dir(r.FilePath)
			refs, err := storage.ReadReferences(skillDir)
			if err == nil && len(refs) > 0 {
				result.References = make([]SkillReference, len(refs))
				for i, ref := range refs {
					result.References[i] = SkillReference{Name: ref.Name, Content: ref.Content}
				}
			}
		}
	case "tool":
		binary, homepage := extractToolMeta(r.Metadata)
		result.Binary = binary
		result.Homepage = homepage

		readPath := r.FilePath
		if _, statErr := os.Stat(readPath); statErr != nil {
			clean := filepath.Clean(r.Name + ".yaml")
			if strings.Contains(clean, "..") {
				return nil, fmt.Errorf("invalid tool path")
			}
			readPath = filepath.Join(s.DataDir, "Tools", clean)
		}
		config, readErr := os.ReadFile(readPath)
		if readErr != nil {
			return nil, fmt.Errorf("read tool config: %w", readErr)
		}
		result.Config = string(config)
	}

	return result, nil
}
