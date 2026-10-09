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

const SearchContractVersion = "security-concepts-v4"

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

	// Products, frameworks and named tooling. These are identity concepts, the
	// same kind already carried by java / php / yii / learun: a word that names
	// *what* is being attacked rather than *how*. Without them the planner has no
	// evidence about the query, so a prose phrasing reports no recognised concept
	// and offers no retry.
	//
	// Every alias here must earn its place twice over: it has to occur in the
	// corpus, and it must not be a token-superset of a narrower alias in the same
	// concept. A redundant pair such as "tomcat" plus "apache tomcat" renders as
	// (tomcat OR (apache AND tomcat)), and FTS5 sums a row's contribution per
	// matching OR branch, so a row matching both scores about twice as strongly
	// (measured 2.52x) for no reason -- which then tightens the relevance cutoff
	// and silently shrinks every reported total for that query.
	{ID: "tomcat", Aliases: []string{"tomcat"}, Role: ConceptRoleIdentity},
	{ID: "nacos", Aliases: []string{"nacos"}, Role: ConceptRoleIdentity},
	{ID: "fastjson", Aliases: []string{"fastjson"}, Role: ConceptRoleIdentity},
	{ID: "shiro", Aliases: []string{"shiro"}, Role: ConceptRoleIdentity},
	{ID: "spring", Aliases: []string{"spring"}, Role: ConceptRoleIdentity},
	{ID: "actuator", Aliases: []string{"actuator"}, Role: ConceptRoleIdentity},
	{ID: "redis", Aliases: []string{"redis"}, Role: ConceptRoleIdentity},
	{ID: "mysql", Aliases: []string{"mysql"}, Role: ConceptRoleIdentity},
	{ID: "sqlmap", Aliases: []string{"sqlmap"}, Role: ConceptRoleIdentity},
	{ID: "docker", Aliases: []string{"docker"}, Role: ConceptRoleIdentity},
	{ID: "kerberoasting", Aliases: []string{"kerberoasting"}, Role: ConceptRoleIdentity},
	{ID: "hashcat", Aliases: []string{"hashcat"}, Role: ConceptRoleIdentity},

	// Vulnerability categories the corpus names in Chinese but the planner did
	// not carry. Topic role: these describe *how*, so a retry built from them is
	// narrower than the question rather than narrower than the subject.
	{ID: "unauthorized_access", Aliases: []string{"未授权"}, Role: ConceptRoleTopic},
	{ID: "container_escape", Aliases: []string{"逃逸"}, Role: ConceptRoleTopic},
	{ID: "av_evasion", Aliases: []string{"免杀"}, Role: ConceptRoleTopic},
	{ID: "weak_credentials", Aliases: []string{"弱口令"}, Role: ConceptRoleTopic},
	{ID: "blind_injection", Aliases: []string{"盲注"}, Role: ConceptRoleTopic},
	{ID: "brute_force", Aliases: []string{"爆破"}, Role: ConceptRoleTopic},
	{ID: "port_scanning", Aliases: []string{"端口扫描"}, Role: ConceptRoleTopic},
	{ID: "lateral_movement", Aliases: []string{"横向移动"}, Role: ConceptRoleTopic},
	{ID: "delegation_attack", Aliases: []string{"委派"}, Role: ConceptRoleTopic},
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
		if err := checkAliasSubsumption(concept); err != nil {
			return nil, err
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

// checkAliasSubsumption rejects an alias whose tokens already contain every
// token of another alias in the same concept.
//
// Such a pair renders as a redundant OR branch and FTS5 scores a row once per
// matching branch, so a row matching both is scored about twice as strongly as
// the same row matching only the narrower alias. Since trimByRelevance derives
// its cutoff from the best score in the list, that inflation silently tightens
// the cutoff and shrinks the reported total: `tomcat` plus `apache tomcat`
// measured -17.78 against -7.07 for `tomcat` alone, and `spring` plus
// `spring boot` reached 3.13x. The wider alias contributes no row the narrower
// one does not already match, so dropping it loses nothing.
func checkAliasSubsumption(concept SecurityConcept) error {
	for _, outer := range concept.Aliases {
		outerTokens := Tokenize(outer)
		if len(outerTokens) == 0 {
			continue
		}
		for _, inner := range concept.Aliases {
			if inner == outer {
				continue
			}
			innerTokens := Tokenize(inner)
			if len(innerTokens) == 0 || len(innerTokens) >= len(outerTokens) {
				continue
			}
			if containsAllTokens(outerTokens, innerTokens) {
				return fmt.Errorf(
					"security concept %q alias %q is subsumed by %q; the wider alias inflates bm25 and tightens the relevance cutoff",
					concept.ID, outer, inner,
				)
			}
		}
	}
	return nil
}

func containsAllTokens(haystack, needles []string) bool {
	set := make(map[string]struct{}, len(haystack))
	for _, t := range haystack {
		set[t] = struct{}{}
	}
	for _, n := range needles {
		if _, ok := set[n]; !ok {
			return false
		}
	}
	return true
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
	// DroppedTerms are the groups this retry left out: the words that were
	// blocking the original query. Naming them lets the caller add back anything
	// that mattered.
	DroppedTerms []string
	// Hits is the number of rows this retry matches, measured against the corpus
	// that produced it. Zero means the retry was not verified and must not be
	// offered; the caller can use the value to order or filter suggestions.
	Hits int
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

// RetryCounter reports how many rows a candidate query would match, so the retry
// builder can tell which words are blocking a zero-result query.
type RetryCounter func(query string) (int, error)

// BuildNoMatchRetryQueries finds the words that are blocking a zero-result
// query: the smallest set of groups whose removal makes the query match.
//
// The builder this replaced stitched together concepts the planner had already
// classified. That assumes the blocking words are exactly the unclassified ones,
// and it fails in the two shapes that matter most. A prose query with a single
// recognised concept ("kerberoasting 怎么 打") suggested that concept on its own
// — retrying the query that had just failed, minus one word. And a query mixing
// an unclassified product name with a classified topic ("landray ekp admin.do
// bypass captcha datasource") suggested the topic alone, dropping the words that
// identify the thing asked about.
//
// Classifying a word is not the same as knowing whether the corpus contains it.
// "bypass" is a recognised topic and can still be what blocks a query; a CVE id
// is unrecognised and precise. So this asks the corpus instead: try dropping one
// group, then two, and take the first level where something matches. The words
// that had to go are the blocking words, and they are what DroppedTerms reports.
//
// Two rules keep the result usable:
//
//   - A candidate may never drop an identity group. Identities name the product
//     or technology the caller asked about, so a retry that loses one is about
//     something else. Without this rule the search prefers dropping the identity,
//     because a rare product name is usually blocking more than a filler word is:
//     "tomcat 弱口令 怎么 打" would suggest "弱口令 怎么" over "tomcat 弱口令".
//   - Every candidate is verified to match before it is offered, so a retry is a
//     query that returned rows, not a query that might. Filler is handled by that
//     measurement rather than by a stopword list, which is the only way it can
//     work here: word frequency does not separate filler from content in this
//     corpus. "怎么" appears in 2 documents and "打" in 4, while "利用" appears in
//     194 and "用" in 85 — the prose words agents write are rarer than the
//     security terms they are attached to, so a frequency-based filter would
//     delete the subject and keep the noise.
//
// Only the minimum drop level is reported. A deeper level describes a query that
// lost more of what was asked, and offering it would suggest discarding signal
// the caller did not ask to discard.
func BuildNoMatchRetryQueries(groups []QueryGroup, resourceType string, count RetryCounter) []FocusedRetryQuery {
	const (
		maxIdentityGroups = 4
		maxDroppedGroups  = 2
		maxRetries        = 3
	)

	if count == nil || len(groups) == 0 {
		return nil
	}

	identities := 0
	for _, group := range groups {
		if group.Role == ConceptRoleIdentity {
			identities++
		}
	}
	// Four identities already fill the focused-query budget, leaving no room to
	// add the topic that would make a retry narrower than the original query.
	if identities >= maxIdentityGroups {
		return nil
	}

	var retries []FocusedRetryQuery
	for dropCount := 1; dropCount <= maxDroppedGroups; dropCount++ {
		level := make([]FocusedRetryQuery, 0)
		for _, dropped := range dropCombinations(len(groups), dropCount) {
			keep := make([]string, 0, len(groups)-dropCount)
			blocked := make([]string, 0, dropCount)
			dropsIdentity := false
			for index, group := range groups {
				if dropped[index] {
					blocked = append(blocked, group.Original)
					if group.Role == ConceptRoleIdentity {
						dropsIdentity = true
					}
					continue
				}
				keep = append(keep, group.Original)
			}
			if dropsIdentity || len(keep) == 0 {
				continue
			}
			candidate := strings.Join(keep, " ")
			hits, err := count(candidate)
			if err != nil || hits == 0 {
				continue
			}
			level = append(level, FocusedRetryQuery{
				Query: candidate,
				Type:  resourceType,
				// Copied per retry so a caller appending to one does not mutate
				// the rest. Nil when nothing was dropped, which omits the field.
				DroppedTerms: append([]string(nil), blocked...),
				Hits:         hits,
			})
		}
		if len(level) == 0 {
			continue
		}
		// Rarest first, so the tightest suggestion the corpus can support leads.
		// The sort is stable over the enumeration order, which follows group
		// order, so equal counts keep the caller's own phrasing ahead.
		sort.SliceStable(level, func(i, j int) bool { return level[i].Hits < level[j].Hits })
		if len(level) > maxRetries {
			level = level[:maxRetries]
		}
		retries = level
		break
	}
	return retries
}

// dropCombinations enumerates the index sets of size dropCount over n items, in
// ascending lexicographic order, so the enumeration is deterministic.
func dropCombinations(n, dropCount int) []map[int]bool {
	if dropCount <= 0 || dropCount > n {
		return nil
	}
	combinations := make([]map[int]bool, 0)
	current := make([]int, dropCount)
	var walk func(start, depth int)
	walk = func(start, depth int) {
		if depth == dropCount {
			dropped := make(map[int]bool, dropCount)
			for _, index := range current {
				dropped[index] = true
			}
			combinations = append(combinations, dropped)
			return
		}
		for index := start; index < n; index++ {
			current[depth] = index
			walk(index+1, depth+1)
		}
	}
	walk(0, 0)
	return combinations
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
