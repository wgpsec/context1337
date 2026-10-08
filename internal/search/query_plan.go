package search

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/wgpsec/context1337/internal/transliterate"
)

const (
	maxRawQueryBytes = 256
	maxQueryGroups   = 8
	maxQueryAtoms    = 48
)

const SearchContractVersion = "security-concepts-v3"

type SecurityConcept struct {
	ID      string
	Aliases []string
	Role    ConceptRole
}

type ConceptRole string

const (
	ConceptRoleIdentity ConceptRole = "identity"
	ConceptRoleTopic    ConceptRole = "topic"
	ConceptRoleContext  ConceptRole = "context"
)

type QueryGroup struct {
	ConceptID    string
	Original     string
	Alternatives []string
	Role         ConceptRole
	Anchor       bool
}

type QueryPlan struct {
	RawQuery           string
	Groups             []QueryGroup
	FTSExpression      string
	ExactFTSExpression string
	Version            string
}

type QueryTransliteration struct {
	From string
	To   string
}

type PinyinFallback struct {
	Query            string
	Transliterations []QueryTransliteration
}

type QueryComplexityError struct {
	Dimension string
	Actual    int
	Maximum   int
	Groups    []QueryGroup
}

func (e *QueryComplexityError) Error() string {
	switch e.Dimension {
	case "raw_bytes":
		return fmt.Sprintf("query too long: %d bytes (max %d)", e.Actual, e.Maximum)
	case "semantic_groups":
		return fmt.Sprintf("too many search concepts: %d (max %d)", e.Actual, e.Maximum)
	case "fts_atoms":
		return fmt.Sprintf("too many search atoms: %d (max %d)", e.Actual, e.Maximum)
	default:
		return fmt.Sprintf("query too complex: %d (max %d)", e.Actual, e.Maximum)
	}
}

var securityConcepts = []SecurityConcept{
	{ID: "jwt", Aliases: []string{"jwt", "json web token"}, Role: ConceptRoleIdentity},
	{ID: "java", Aliases: []string{"java"}, Role: ConceptRoleIdentity},
	{ID: "php", Aliases: []string{"php"}, Role: ConceptRoleIdentity},
	{ID: "yii", Aliases: []string{"yii"}, Role: ConceptRoleIdentity},
	{ID: "sql_injection", Aliases: []string{"sql injection", "sqli", "sql注入"}, Role: ConceptRoleTopic},
	{ID: "privilege_escalation", Aliases: []string{"privilege escalation", "privesc", "权限提升", "提权"}, Role: ConceptRoleTopic},
	{ID: "linux", Aliases: []string{"linux"}, Role: ConceptRoleIdentity},
	{ID: "learun", Aliases: []string{"learun", "力软"}, Role: ConceptRoleIdentity},
	{ID: "algorithm", Aliases: []string{"algorithm", "算法"}, Role: ConceptRoleContext},
	{ID: "confusion", Aliases: []string{"confusion", "混淆"}, Role: ConceptRoleTopic},
	{ID: "bypass", Aliases: []string{"bypass", "绕过"}, Role: ConceptRoleTopic},
	{ID: "deserialization", Aliases: []string{"deserialization", "反序列化"}, Role: ConceptRoleTopic},
	{ID: "file_inclusion", Aliases: []string{"file inclusion", "文件包含"}, Role: ConceptRoleTopic},
	{ID: "log_poisoning", Aliases: []string{"log poisoning", "日志投毒"}, Role: ConceptRoleTopic},
	{ID: "csrf", Aliases: []string{"csrf", "cross-site request forgery", "跨站请求伪造"}, Role: ConceptRoleTopic},
	{ID: "forgery", Aliases: []string{"forgery", "伪造"}, Role: ConceptRoleTopic},
}

var conceptsByAlias = mustBuildConceptAliasIndex(securityConcepts)

func mustBuildConceptAliasIndex(concepts []SecurityConcept) map[string]SecurityConcept {
	index, err := buildConceptAliasIndex(concepts)
	if err != nil {
		panic(err)
	}
	return index
}

func buildConceptAliasIndex(concepts []SecurityConcept) (map[string]SecurityConcept, error) {
	index := make(map[string]SecurityConcept)
	for _, concept := range concepts {
		if len(concept.Aliases) > 6 {
			return nil, fmt.Errorf("security concept %q must have at most 6 aliases", concept.ID)
		}
		for _, alias := range concept.Aliases {
			normalized := normalizeConceptAlias(alias)
			if normalized == "" {
				return nil, fmt.Errorf("security concept %q contains an empty alias", concept.ID)
			}
			if existing, ok := index[normalized]; ok {
				return nil, fmt.Errorf(
					"security alias %q is shared by concepts %q and %q",
					normalized, existing.ID, concept.ID,
				)
			}
			index[normalized] = concept
		}
	}
	return index, nil
}

func normalizeConceptAlias(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func PlanQuery(raw string) (QueryPlan, error) {
	if len(raw) > maxRawQueryBytes {
		return QueryPlan{}, &QueryComplexityError{
			Dimension: "raw_bytes", Actual: len(raw), Maximum: maxRawQueryBytes,
		}
	}
	groups := planSemanticGroups(raw)
	if len(groups) > maxQueryGroups {
		return QueryPlan{}, &QueryComplexityError{
			Dimension: "semantic_groups", Actual: len(groups), Maximum: maxQueryGroups,
			Groups: append([]QueryGroup(nil), groups...),
		}
	}

	expressions := make([]string, 0, len(groups))
	exactExpressions := make([]string, 0, len(groups))
	atomCount := 0
	rendered := make([]QueryGroup, 0, len(groups))
	for _, group := range groups {
		expression, atoms := buildFTSGroup(group.Alternatives)
		if expression == "" {
			// Group carried no searchable atoms (punctuation-only). Drop it so
			// the joined expression never contains an empty operand.
			continue
		}
		rendered = append(rendered, group)
		expressions = append(expressions, expression)
		atomCount += atoms
		exactExpression, _ := buildFTSGroup([]string{group.Original})
		if exactExpression == "" {
			exactExpression = expression
		}
		exactExpressions = append(exactExpressions, exactExpression)
	}
	if atomCount > maxQueryAtoms {
		return QueryPlan{}, &QueryComplexityError{
			Dimension: "fts_atoms", Actual: atomCount, Maximum: maxQueryAtoms,
			Groups: append([]QueryGroup(nil), groups...),
		}
	}

	return QueryPlan{
		RawQuery:           raw,
		Groups:             rendered,
		FTSExpression:      strings.Join(expressions, " AND "),
		ExactFTSExpression: strings.Join(exactExpressions, " AND "),
		Version:            SearchContractVersion,
	}, nil
}

// BuildPinyinFallback returns one deterministic candidate. It transliterates
// only unknown Han-only context groups and preserves every other query group.
func BuildPinyinFallback(plan QueryPlan) (PinyinFallback, bool) {
	const maxTransliteratedGroups = 3

	parts := make([]string, 0, len(plan.Groups))
	mappings := make([]QueryTransliteration, 0, maxTransliteratedGroups)
	for _, group := range plan.Groups {
		part := group.Original
		if group.Role == ConceptRoleContext && group.ConceptID == "" && len(mappings) < maxTransliteratedGroups {
			if converted, ok := transliterate.Pinyin(group.Original); ok {
				part = converted
				mappings = append(mappings, QueryTransliteration{From: group.Original, To: converted})
			}
		}
		parts = append(parts, part)
	}
	if len(mappings) == 0 {
		return PinyinFallback{}, false
	}
	return PinyinFallback{
		Query:            strings.Join(parts, " "),
		Transliterations: mappings,
	}, true
}

type FocusedRetryQuery struct {
	Query string
	Type  string
	// DroppedTerms are the context groups this retry left out. The planner has
	// no way to tell a filler word ("怎么") from a product name ("shiro"), so a
	// narrowing retry necessarily drops both. Reporting them keeps the
	// suggestion auditable instead of silently rewriting the caller's question.
	DroppedTerms []string
}

func BuildFocusedRetryQueries(groups []QueryGroup, resourceType string) []FocusedRetryQuery {
	identities := make([]string, 0)
	topics := make([]string, 0)
	contexts := make([]string, 0)
	for _, group := range groups {
		switch group.Role {
		case ConceptRoleIdentity:
			identities = append(identities, group.Original)
		case ConceptRoleTopic:
			topics = append(topics, group.Original)
		default:
			contexts = append(contexts, group.Original)
		}
	}
	if len(topics) > 0 {
		if len(identities) >= 4 {
			return nil
		}
		retries := make([]FocusedRetryQuery, 0, len(topics))
		for _, topic := range topics {
			parts := append([]string(nil), identities...)
			parts = append(parts, topic)
			remainingSlots := 4 - len(parts)
			if remainingSlots > len(contexts) {
				remainingSlots = len(contexts)
			}
			if remainingSlots > 0 {
				parts = append(parts, contexts[:remainingSlots]...)
			}
			retries = append(retries, FocusedRetryQuery{
				Query: strings.Join(parts, " "), Type: resourceType,
			})
		}
		return retries
	}
	if len(identities) == 0 {
		return nil
	}

	groupsPerRetry := 4 - len(identities)
	if groupsPerRetry < 1 {
		groupsPerRetry = 1
	}
	if len(contexts) == 0 {
		return []FocusedRetryQuery{{Query: strings.Join(identities, " "), Type: resourceType}}
	}

	retries := make([]FocusedRetryQuery, 0, (len(contexts)+groupsPerRetry-1)/groupsPerRetry)
	for start := 0; start < len(contexts); start += groupsPerRetry {
		end := start + groupsPerRetry
		if end > len(contexts) {
			end = len(contexts)
		}
		parts := append([]string(nil), identities...)
		parts = append(parts, contexts[start:end]...)
		retries = append(retries, FocusedRetryQuery{
			Query: strings.Join(parts, " "),
			Type:  resourceType,
		})
	}
	return retries
}

// BuildNoMatchRetryQueries narrows a query that returned nothing down to the
// concepts the planner actually recognised.
//
// The builder this replaced only fired when at least two topic concepts were
// recognised, and it carried every context group into each retry. Both are wrong
// for the query shape an agent actually writes. "拿到 webshell 之后怎么提权"
// recognises one topic and three context groups, so it produced no retry at all;
// and where a retry was produced, carrying context forward re-sent the terms that
// made the query fail in the first place. Measured over eighteen such phrasings,
// those retries hit zero of six offered.
//
// This drops context instead. A context group is by definition a word the
// planner could not classify, so keeping it is what reproduces the failure and
// dropping it leaves only terms with aliases behind (sql_injection carries
// "sql injection" / "sqli" / "sql注入"). The dropped words are reported in
// DroppedTerms because the planner cannot tell filler from a product name: for
// "我想打一个 shiro 反序列化" this suggests "反序列化", which is narrower than what
// was asked. That is why the retry is a suggestion the caller may take or ignore
// (Context1337 never executes it) and why the dropped words travel with it.
//
// Identity groups are kept for the same reason the older builder keeps them: a
// retry that loses "php" stops being about the thing the caller asked about. A
// query whose retry would be empty produces none.
func BuildNoMatchRetryQueries(groups []QueryGroup, resourceType string) []FocusedRetryQuery {
	const maxIdentityGroups = 4

	identities := make([]string, 0)
	topics := make([]string, 0)
	dropped := make([]string, 0)
	for _, group := range groups {
		switch group.Role {
		case ConceptRoleIdentity:
			identities = append(identities, group.Original)
		case ConceptRoleTopic:
			topics = append(topics, group.Original)
		default:
			dropped = append(dropped, group.Original)
		}
	}
	// Four identities already fill the focused-query budget, leaving no room to
	// add the topic that would make a retry narrower than the original query.
	if len(identities) >= maxIdentityGroups {
		return nil
	}

	build := func(parts []string) FocusedRetryQuery {
		return FocusedRetryQuery{
			Query: strings.Join(parts, " "),
			Type:  resourceType,
			// Copied per retry so a caller appending to one does not mutate the
			// rest. Nil when nothing was dropped, which omits the field.
			DroppedTerms: append([]string(nil), dropped...),
		}
	}

	if len(topics) == 0 {
		// No topic to pivot on. The identities alone are still a narrower query
		// than the one that failed, and returning nothing would leave the caller
		// with no suggestion at all.
		if len(identities) == 0 {
			return nil
		}
		return []FocusedRetryQuery{build(identities)}
	}
	if len(identities) == 0 && len(topics) == 1 {
		// A single topic with nothing to qualify it is the original query minus
		// the unrecognised words, which is exactly the suggestion worth making.
		return []FocusedRetryQuery{build(topics)}
	}

	// One retry per topic, so a multi-topic question ("sql注入 提权") yields a
	// query per topic instead of one that still demands both.
	retries := make([]FocusedRetryQuery, 0, len(topics))
	for _, topic := range topics {
		parts := append([]string(nil), identities...)
		parts = append(parts, topic)
		retries = append(retries, build(parts))
	}
	return retries
}

type conceptSpan struct {
	start   int
	end     int
	alias   string
	concept SecurityConcept
}

func planSemanticGroups(raw string) []QueryGroup {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" {
		return nil
	}

	spans := matchConceptSpans(normalized)
	groups := make([]QueryGroup, 0, len(spans)+1)
	seenConcepts := make(map[string]struct{})
	appendExactGroups := func(value string) {
		for _, field := range strings.Fields(value) {
			exact := strings.TrimFunc(field, func(r rune) bool {
				return unicode.IsSpace(r) || strings.ContainsRune(",;，；|()[]{}", r)
			})
			if exact == "" {
				continue
			}
			groups = append(groups, QueryGroup{
				Original:     exact,
				Alternatives: []string{exact},
				Role:         ConceptRoleContext,
			})
		}
	}

	previousEnd := 0
	for _, span := range spans {
		if span.start > previousEnd {
			appendExactGroups(normalized[previousEnd:span.start])
		}
		if _, exists := seenConcepts[span.concept.ID]; !exists {
			groups = append(groups, QueryGroup{
				ConceptID:    span.concept.ID,
				Original:     span.alias,
				Alternatives: append([]string(nil), span.concept.Aliases...),
				Role:         span.concept.Role,
				Anchor:       span.concept.Role == ConceptRoleIdentity,
			})
			seenConcepts[span.concept.ID] = struct{}{}
		}
		previousEnd = span.end
	}
	if previousEnd < len(normalized) {
		appendExactGroups(normalized[previousEnd:])
	}
	return groups
}

func matchConceptSpans(text string) []conceptSpan {
	type conceptAlias struct {
		alias   string
		concept SecurityConcept
	}
	aliases := make([]conceptAlias, 0, len(conceptsByAlias))
	for alias, concept := range conceptsByAlias {
		aliases = append(aliases, conceptAlias{alias: alias, concept: concept})
	}
	sort.Slice(aliases, func(i, j int) bool {
		if len(aliases[i].alias) != len(aliases[j].alias) {
			return len(aliases[i].alias) > len(aliases[j].alias)
		}
		return aliases[i].alias < aliases[j].alias
	})

	spans := make([]conceptSpan, 0)
	for _, candidate := range aliases {
		searchFrom := 0
		for searchFrom < len(text) {
			relative := strings.Index(text[searchFrom:], candidate.alias)
			if relative < 0 {
				break
			}
			start := searchFrom + relative
			end := start + len(candidate.alias)
			if isASCIIConceptAlias(candidate.alias) && !hasConceptBoundaries(text, start, end) {
				searchFrom = end
				continue
			}
			overlaps := false
			for _, span := range spans {
				if start < span.end && end > span.start {
					overlaps = true
					break
				}
			}
			if !overlaps {
				spans = append(spans, conceptSpan{
					start: start, end: end, alias: text[start:end], concept: candidate.concept,
				})
			}
			searchFrom = end
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	return spans
}

func isASCIIConceptAlias(value string) bool {
	for _, r := range value {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func hasConceptBoundaries(text string, start, end int) bool {
	if start > 0 {
		before, _ := utf8.DecodeLastRuneInString(text[:start])
		if unicode.IsLetter(before) || unicode.IsDigit(before) {
			return false
		}
	}
	if end < len(text) {
		after, _ := utf8.DecodeRuneInString(text[end:])
		if unicode.IsLetter(after) || unicode.IsDigit(after) {
			return false
		}
	}
	return true
}

// buildFTSGroup renders one query group as an FTS5 expression. Alternatives
// that tokenize to nothing (punctuation-only input such as "..." or "!!!") are
// dropped; when every alternative is dropped the group yields "" rather than
// "()", because an empty group is not a valid MATCH expression and SQLite
// rejects it with `fts5: syntax error near ")"`.
func buildFTSGroup(alternatives []string) (string, int) {
	expressions := make([]string, 0, len(alternatives))
	atomCount := 0
	for _, alternative := range alternatives {
		atoms := Tokenize(alternative)
		if len(atoms) == 0 {
			continue
		}
		atomCount += len(atoms)
		escaped := make([]string, 0, len(atoms))
		for _, atom := range atoms {
			escaped = append(escaped, quoteFTSToken(atom))
		}
		expression := strings.Join(escaped, " AND ")
		if len(escaped) > 1 {
			expression = "(" + expression + ")"
		}
		expressions = append(expressions, expression)
	}
	switch len(expressions) {
	case 0:
		return "", atomCount
	case 1:
		return expressions[0], atomCount
	default:
		return "(" + strings.Join(expressions, " OR ") + ")", atomCount
	}
}

func quoteFTSToken(token string) string {
	return `"` + strings.ReplaceAll(token, `"`, `""`) + `"`
}
