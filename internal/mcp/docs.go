package mcp

import (
	"context"
	"fmt"

	"github.com/Esonhugh/context1337/internal/search"
)

// --- list_docs ---

type ListDocsInput struct {
	Offset int `json:"offset,omitempty" jsonschema:"Pagination offset (default 0)"`
	Limit  int `json:"limit,omitempty"  jsonschema:"Max results (default 50)"`
}

type DocSummary struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Source      string `json:"source"`
}

type DocListResult struct {
	Total  int          `json:"total"`
	Offset int          `json:"offset"`
	Limit  int          `json:"limit"`
	Items  []DocSummary `json:"items"`
}

func (s *Service) ListDocs(ctx context.Context, in ListDocsInput) (*DocListResult, error) {
	if in.Limit <= 0 {
		in.Limit = 50
	}
	result, err := search.ListByType(s.DB, search.ListQuery{
		Type: "doc", Offset: in.Offset, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	items := make([]DocSummary, len(result.Items))
	for i, r := range result.Items {
		items[i] = DocSummary{Name: r.Name, Description: r.Description, Source: r.Source}
	}
	return &DocListResult{Total: result.Total, Offset: in.Offset, Limit: in.Limit, Items: items}, nil
}

// --- search_doc ---

type SearchDocInput struct {
	Query  string `json:"query"            jsonschema:"Search keyword"`
	Offset int    `json:"offset,omitempty" jsonschema:"Pagination offset (default 0)"`
	Limit  int    `json:"limit,omitempty"  jsonschema:"Max results (default 10)"`
}

type DocSearchResult struct {
	Total  int          `json:"total"`
	Offset int          `json:"offset"`
	Limit  int          `json:"limit"`
	Items  []DocSummary `json:"items"`
}

func (s *Service) SearchDoc(ctx context.Context, in SearchDocInput) (*DocSearchResult, error) {
	if in.Limit <= 0 {
		in.Limit = 10
	}
	results, total, err := search.Search(s.DB, search.SearchQuery{
		Query: in.Query, Type: "doc", Offset: in.Offset, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	items := make([]DocSummary, len(results))
	for i, r := range results {
		items[i] = DocSummary{Name: r.Name, Description: r.Description, Source: r.Source}
	}
	return &DocSearchResult{Total: total, Offset: in.Offset, Limit: in.Limit, Items: items}, nil
}

// --- get_doc ---

type GetDocInput struct {
	Name string `json:"name" jsonschema:"Document name e.g. Cheatsheet, Checklist.zh-cn"`
}

type DocDetail struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Body        string `json:"body"`
}

func (s *Service) GetDoc(ctx context.Context, in GetDocInput) (*DocDetail, error) {
	r, err := search.GetByName(s.DB, "doc", in.Name)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("doc %q not found", in.Name)
	}
	return &DocDetail{Name: r.Name, Description: r.Description, Body: r.Body}, nil
}
