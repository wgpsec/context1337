package mcp

import (
	"context"

	"github.com/Esonhugh/context1337/internal/search"
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
