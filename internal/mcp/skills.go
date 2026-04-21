package mcp

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Esonhugh/context1337/internal/search"
)

// Service holds shared dependencies for all MCP handlers.
type Service struct {
	DB      *sql.DB
	DataDir string
}

// --- list_skills ---

type ListSkillsInput struct {
	Category   string `json:"category,omitempty"   jsonschema:"Filter by category: exploit|recon|tool|cloud|ctf|lateral|evasion|malware|dfir|threat-intel|ai-security|code-audit|postexploit|general"`
	Difficulty string `json:"difficulty,omitempty" jsonschema:"Filter by difficulty: easy|medium|hard"`
	Offset     int    `json:"offset,omitempty"     jsonschema:"Pagination offset (default 0)"`
	Limit      int    `json:"limit,omitempty"      jsonschema:"Max results (default 50)"`
}

type SkillSummary struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Tags        string `json:"tags"`
	Difficulty  string `json:"difficulty"`
	Source      string `json:"source"`
}

type SkillListResult struct {
	Total  int            `json:"total"`
	Offset int            `json:"offset"`
	Limit  int            `json:"limit"`
	Items  []SkillSummary `json:"items"`
}

func (s *Service) ListSkills(ctx context.Context, in ListSkillsInput) (*SkillListResult, error) {
	if in.Limit <= 0 {
		in.Limit = 50
	}
	result, err := search.ListByType(s.DB, search.ListQuery{
		Type: "skill", Category: in.Category, Difficulty: in.Difficulty,
		Offset: in.Offset, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	items := make([]SkillSummary, len(result.Items))
	for i, r := range result.Items {
		items[i] = SkillSummary{
			Name: r.Name, Description: r.Description, Category: r.Category,
			Tags: r.Tags, Difficulty: r.Difficulty, Source: r.Source,
		}
	}
	return &SkillListResult{Total: result.Total, Offset: in.Offset, Limit: in.Limit, Items: items}, nil
}

// --- search_skill ---

type SearchSkillInput struct {
	Query      string `json:"query"               jsonschema:"Search query keywords"`
	Category   string `json:"category,omitempty"   jsonschema:"Filter by category: exploit|recon|tool|cloud|ctf|lateral|evasion|malware|dfir|threat-intel|ai-security|code-audit|postexploit|general"`
	Difficulty string `json:"difficulty,omitempty" jsonschema:"Filter by difficulty: easy|medium|hard"`
	Offset     int    `json:"offset,omitempty"     jsonschema:"Pagination offset (default 0)"`
	Limit      int    `json:"limit,omitempty"      jsonschema:"Max results (default 10)"`
}

type SkillSearchResult struct {
	Total  int            `json:"total"`
	Offset int            `json:"offset"`
	Limit  int            `json:"limit"`
	Items  []SkillSummary `json:"items"`
}

func (s *Service) SearchSkill(ctx context.Context, in SearchSkillInput) (*SkillSearchResult, error) {
	if in.Limit <= 0 {
		in.Limit = 10
	}
	results, total, err := search.Search(s.DB, search.SearchQuery{
		Query: in.Query, Type: "skill", Category: in.Category,
		Difficulty: in.Difficulty, Offset: in.Offset, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	items := make([]SkillSummary, len(results))
	for i, r := range results {
		items[i] = SkillSummary{
			Name: r.Name, Description: r.Description, Category: r.Category,
			Tags: r.Tags, Difficulty: r.Difficulty, Source: r.Source,
		}
	}
	return &SkillSearchResult{Total: total, Offset: in.Offset, Limit: in.Limit, Items: items}, nil
}

// --- get_skill ---

type GetSkillInput struct {
	Name  string `json:"name"            jsonschema:"Skill name"`
	Depth string `json:"depth,omitempty" jsonschema:"Loading depth: metadata|summary|full (default summary)"`
}

type SkillDetail struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Tags        string `json:"tags"`
	Difficulty  string `json:"difficulty"`
	Source      string `json:"source"`
	Body        string `json:"body,omitempty"`
}

func (s *Service) GetSkill(ctx context.Context, in GetSkillInput) (*SkillDetail, error) {
	if in.Depth == "" {
		in.Depth = "summary"
	}
	r, err := search.GetByName(s.DB, "skill", in.Name)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("skill %q not found", in.Name)
	}
	detail := &SkillDetail{
		Name: r.Name, Description: r.Description, Category: r.Category,
		Tags: r.Tags, Difficulty: r.Difficulty, Source: r.Source,
	}
	switch in.Depth {
	case "metadata":
		// No body
	case "summary":
		detail.Body = r.Body
	case "full":
		detail.Body = r.Body
		// TODO Phase 2: append references/ directory content
	}
	return detail, nil
}
