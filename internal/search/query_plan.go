package search

import (
	"fmt"
	"strings"
)

const (
	maxRawQueryBytes = 256
	maxQueryGroups   = 8
)

const SearchContractVersion = "security-concepts-v1"

type SecurityConcept struct {
	ID      string
	Aliases []string
	Anchor  bool
}

type QueryGroup struct {
	ConceptID    string
	Original     string
	Alternatives []string
	Anchor       bool
}

type QueryPlan struct {
	RawQuery      string
	Groups        []QueryGroup
	FTSExpression string
	Version       string
}

var securityConcepts = []SecurityConcept{
	{ID: "jwt", Aliases: []string{"jwt", "json web token"}, Anchor: true},
	{ID: "java", Aliases: []string{"java"}, Anchor: true},
	{ID: "php", Aliases: []string{"php"}, Anchor: true},
	{ID: "sql_injection", Aliases: []string{"sql injection", "sqli", "sql注入"}, Anchor: true},
	{ID: "privilege_escalation", Aliases: []string{"privilege escalation", "privesc", "权限提升", "提权"}, Anchor: true},
	{ID: "linux", Aliases: []string{"linux"}, Anchor: true},
	{ID: "algorithm", Aliases: []string{"algorithm", "算法"}},
	{ID: "confusion", Aliases: []string{"confusion", "混淆"}},
	{ID: "bypass", Aliases: []string{"bypass", "绕过"}},
}

var conceptsByAlias = buildConceptAliasIndex(securityConcepts)

func buildConceptAliasIndex(concepts []SecurityConcept) map[string]SecurityConcept {
	index := make(map[string]SecurityConcept)
	for _, concept := range concepts {
		for _, alias := range concept.Aliases {
			index[normalizeConceptAlias(alias)] = concept
		}
	}
	return index
}

func normalizeConceptAlias(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func PlanQuery(raw string) (QueryPlan, error) {
	if len(raw) > maxRawQueryBytes {
		return QueryPlan{}, fmt.Errorf(
			"query too long: %d bytes (max %d)",
			len(raw),
			maxRawQueryBytes,
		)
	}
	tokens := Tokenize(raw)
	if len(tokens) > maxQueryGroups {
		return QueryPlan{}, fmt.Errorf(
			"too many search concepts: %d (max %d)",
			len(tokens),
			maxQueryGroups,
		)
	}

	groups := make([]QueryGroup, 0, len(tokens))
	expressions := make([]string, 0, len(tokens))
	for _, token := range tokens {
		group := QueryGroup{
			Original:     token,
			Alternatives: []string{token},
		}
		if concept, ok := conceptsByAlias[normalizeConceptAlias(token)]; ok {
			group.ConceptID = concept.ID
			group.Alternatives = append([]string(nil), concept.Aliases...)
			group.Anchor = concept.Anchor
		}
		groups = append(groups, group)
		expressions = append(expressions, buildFTSGroup(group.Alternatives))
	}

	return QueryPlan{
		RawQuery:      raw,
		Groups:        groups,
		FTSExpression: strings.Join(expressions, " AND "),
		Version:       SearchContractVersion,
	}, nil
}

func buildFTSGroup(alternatives []string) string {
	escaped := make([]string, 0, len(alternatives))
	for _, alternative := range alternatives {
		escaped = append(escaped, quoteFTSToken(alternative))
	}
	if len(escaped) == 1 {
		return escaped[0]
	}
	return "(" + strings.Join(escaped, " OR ") + ")"
}

func quoteFTSToken(token string) string {
	return `"` + strings.ReplaceAll(token, `"`, `""`) + `"`
}
