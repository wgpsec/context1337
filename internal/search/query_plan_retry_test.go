package search

import (
	"fmt"
	"strings"
	"testing"
)

func planGroups(t *testing.T, query string) []QueryGroup {
	t.Helper()
	plan, err := PlanQuery(query)
	if err != nil {
		t.Fatalf("PlanQuery(%q): %v", query, err)
	}
	return plan.Groups
}

// retryCorpus builds a counter over a toy corpus. Each document is a string, and
// a query matches when some document contains every token of it, which is the
// AND semantics the real index applies.
func retryCorpus(documents ...string) RetryCounter {
	indexed := make([][]string, 0, len(documents))
	for _, document := range documents {
		indexed = append(indexed, Tokenize(document))
	}
	return func(query string) (int, error) {
		tokens := Tokenize(query)
		if len(tokens) == 0 {
			return 0, nil
		}
		hits := 0
		for _, document := range indexed {
			if containsEveryToken(document, tokens) {
				hits++
			}
		}
		return hits, nil
	}
}

func containsEveryToken(document, tokens []string) bool {
	for _, token := range tokens {
		found := false
		for _, candidate := range document {
			if candidate == token {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func retryQueries(retries []FocusedRetryQuery) []string {
	queries := make([]string, len(retries))
	for index, retry := range retries {
		queries[index] = retry.Query
	}
	return queries
}

// The blocking words are the ones whose removal makes the query match. Here only
// dropping both unrecognised words reaches the corpus, so both are reported.
func TestBuildNoMatchRetryQueries_DropsTheBlockingWords(t *testing.T) {
	groups := planGroups(t, "sql注入 怎么 利用")
	retries := BuildNoMatchRetryQueries(groups, "skill", retryCorpus("sql注入"))

	if len(retries) != 1 {
		t.Fatalf("retries = %#v, want one", retries)
	}
	if retries[0].Query != "sql注入" {
		t.Fatalf("retry query = %q, want the topic that still matches", retries[0].Query)
	}
	if fmt.Sprint(retries[0].DroppedTerms) != "[怎么 利用]" {
		t.Fatalf("dropped terms = %v, want the words that blocked the match", retries[0].DroppedTerms)
	}
	if retries[0].Hits != 1 {
		t.Fatalf("hits = %d, want the measured match count", retries[0].Hits)
	}
	if retries[0].Type != "skill" {
		t.Fatalf("retry type = %q, want the caller's type filter preserved", retries[0].Type)
	}
}

// The prose shape an agent writes: one topic buried in three context groups. The
// older builder stitched recognised concepts together, so it suggested the topic
// alone; this keeps the words that identify the thing asked about, because they
// are what the corpus actually holds.
func TestBuildNoMatchRetryQueries_KeepsTheWordsThatMatch(t *testing.T) {
	groups := planGroups(t, "拿到 webshell 之后怎么提权")
	retries := BuildNoMatchRetryQueries(groups, "", retryCorpus("拿到 webshell 提权", "提权"))

	if len(retries) != 1 {
		t.Fatalf("retries = %#v, want one", retries)
	}
	if retries[0].Query != "拿到 webshell 提权" {
		t.Fatalf("retry query = %q, want the query minus its blocking word", retries[0].Query)
	}
	if fmt.Sprint(retries[0].DroppedTerms) != "[之后怎么]" {
		t.Fatalf("dropped terms = %v, want only the word that blocked the match", retries[0].DroppedTerms)
	}
}

// A candidate that drops an identity is never offered, even when it matches. The
// corpus here makes "反序列化 服务器" reachable by dropping the identity "php",
// and that is reachable at the same level as the identity-preserving candidate.
func TestBuildNoMatchRetryQueries_KeepsIdentity(t *testing.T) {
	groups := planGroups(t, "php 反序列化 怎么利用 服务器")
	retries := BuildNoMatchRetryQueries(groups, "skill",
		retryCorpus("反序列化 服务器", "php 反序列化"))

	if len(retries) != 1 {
		t.Fatalf("retries = %#v, want the identity-preserving candidate only", retries)
	}
	if retries[0].Query != "php 反序列化" {
		t.Fatalf("retry query = %q, want identity plus topic", retries[0].Query)
	}
	if fmt.Sprint(retries[0].DroppedTerms) != "[怎么利用 服务器]" {
		t.Fatalf("dropped terms = %v, want the blocking words", retries[0].DroppedTerms)
	}
}

// One retry per blocking word at the minimum level, so a multi-topic question
// yields a query per topic instead of one that still demands both.
func TestBuildNoMatchRetryQueries_OneRetryPerBlockingWord(t *testing.T) {
	groups := planGroups(t, "php sql注入 提权")
	retries := BuildNoMatchRetryQueries(groups, "skill", retryCorpus("php sql注入", "php 提权"))

	got := retryQueries(retries)
	// Dropping the earlier group is enumerated first, and both candidates match
	// equally often, so the stable sort leaves that order intact.
	want := []string{"php 提权", "php sql注入"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("retries = %v, want %v", got, want)
	}
}

// A query whose words the corpus does not hold has no blocking word to find, so
// nothing is suggested. This is the property the closure design calls "do not
// guess an identity": a candidate is offered only after it was measured.
func TestBuildNoMatchRetryQueries_UnknownWordsReturnNothing(t *testing.T) {
	groups := planGroups(t, "zzzznothing 怎么 打")
	if retries := BuildNoMatchRetryQueries(groups, "", retryCorpus("sql注入", "提权")); len(retries) != 0 {
		t.Fatalf("retries = %#v, want none when no candidate matches", retries)
	}
}

// Identities fill the focused-query budget, so there is no room for the topic
// that would make a retry narrower than the original query. The budget is
// checked before any candidate is measured, so a corpus that matches everything
// still yields nothing.
func TestBuildNoMatchRetryQueries_IdentityBudgetExhausted(t *testing.T) {
	groups := planGroups(t, "php java linux jwt sql注入 提权")
	countsNothing := func(string) (int, error) {
		t.Fatal("the identity budget must be enforced before counting")
		return 0, nil
	}
	if retries := BuildNoMatchRetryQueries(groups, "skill", countsNothing); len(retries) != 0 {
		t.Fatalf("retries = %#v, want none once identities fill every slot", retries)
	}
}

// Every retry must be executable, deterministic and verified: the caller sends it
// straight back to this same planner, and a suggestion that cannot match is worse
// than no suggestion.
func TestBuildNoMatchRetryQueries_RetriesAreExecutableAndStable(t *testing.T) {
	corpus := retryCorpus("sql注入", "拿到 webshell 提权", "php sql注入", "php 反序列化")
	for _, query := range []string{
		"sql注入 怎么 利用",
		"拿到 webshell 之后怎么提权",
		"php sql注入 提权",
		"php 反序列化 怎么利用 服务器",
	} {
		first := BuildNoMatchRetryQueries(planGroups(t, query), "skill", corpus)
		second := BuildNoMatchRetryQueries(planGroups(t, query), "skill", corpus)
		if fmt.Sprint(first) != fmt.Sprint(second) {
			t.Fatalf("%q: retries are not deterministic:\n%#v\n%#v", query, first, second)
		}
		for _, retry := range first {
			if _, err := PlanQuery(retry.Query); err != nil {
				t.Fatalf("%q produced unplannable retry %q: %v", query, retry.Query, err)
			}
			if retry.Hits < 1 {
				t.Fatalf("%q offered retry %q with %d hits, want a verified match",
					query, retry.Query, retry.Hits)
			}
		}
	}
}

// The dropped terms are per-retry copies. A caller that appends to one retry's
// list must not alter the others.
func TestBuildNoMatchRetryQueries_DroppedTermsAreIndependent(t *testing.T) {
	groups := planGroups(t, "php sql注入 提权 内网")
	retries := BuildNoMatchRetryQueries(groups, "skill",
		retryCorpus("php sql注入", "php 提权"))
	if len(retries) < 2 {
		t.Fatalf("retries = %#v, want at least two", retries)
	}
	before := fmt.Sprint(retries[1].DroppedTerms)
	if before == "[]" {
		t.Fatalf("second retry dropped nothing, so this case cannot detect aliasing")
	}
	retries[0].DroppedTerms = append(retries[0].DroppedTerms, "mutated")
	if after := fmt.Sprint(retries[1].DroppedTerms); after != before {
		t.Fatalf("second retry's dropped terms changed: %s -> %s", before, after)
	}
	if fmt.Sprint(retries[1].DroppedTerms) == fmt.Sprint(retries[0].DroppedTerms) {
		t.Fatalf("both retries share one dropped-terms slice")
	}
}

// Kept honest rather than claimed fixed: a query that is almost entirely filler
// still leaks a filler word once the minimum level forces the candidate down to a
// single group. Only the words the corpus matches survive, so the leak is bounded
// to queries that have no other content to pivot on.
func TestBuildNoMatchRetryQueries_FillerOnlyQueryIsAKnownLimit(t *testing.T) {
	groups := planGroups(t, "zzzznothing 怎么 打")
	retries := BuildNoMatchRetryQueries(groups, "", retryCorpus("怎么 打"))

	if len(retries) != 1 {
		t.Fatalf("retries = %#v, want the single candidate the corpus supports", retries)
	}
	if retries[0].Query != "怎么 打" {
		t.Fatalf("retry query = %q, want the documented limitation", retries[0].Query)
	}
}

// Depth is capped: a query that only starts matching after three groups are gone
// is reported as unrecoverable rather than narrowed past the caller's meaning.
func TestBuildNoMatchRetryQueries_DoesNotNarrowPastTwoGroups(t *testing.T) {
	groups := planGroups(t, "php sql注入 提权 内网")
	// Only "内网" matches, which needs three groups dropped to reach.
	retries := BuildNoMatchRetryQueries(groups, "skill", retryCorpus("内网"))
	if len(retries) != 0 {
		t.Fatalf("retries = %#v, want none beyond the drop limit", retries)
	}
}

// A failing measurement drops the candidate rather than failing the search: the
// caller already has a no_match to return.
func TestBuildNoMatchRetryQueries_CountingFailureYieldsNoRetry(t *testing.T) {
	groups := planGroups(t, "sql注入 怎么 利用")
	failing := func(string) (int, error) { return 0, fmt.Errorf("index unavailable") }
	if retries := BuildNoMatchRetryQueries(groups, "skill", failing); len(retries) != 0 {
		t.Fatalf("retries = %#v, want none when the corpus cannot be measured", retries)
	}
}

// Named products and tooling must be recognised, because a word the planner
// cannot classify makes a prose phrasing produce no retry at all. These are the
// phrasings measured from an agent writing in prose: before the registry carried
// them, every one of these offered nothing to retry with.
func TestPlanQuery_RecognisesNamedProducts(t *testing.T) {
	for _, tc := range []struct {
		query  string
		wantID string
		role   ConceptRole
	}{
		{"kerberoasting 怎么 打", "kerberoasting", ConceptRoleIdentity},
		{"redis 未授权 怎么 利用", "redis", ConceptRoleIdentity},
		{"spring boot actuator 怎么利用", "actuator", ConceptRoleIdentity},
		{"我想打一个 shiro 反序列化", "shiro", ConceptRoleIdentity},
		{"docker 逃逸 怎么做", "docker", ConceptRoleIdentity},
		{"怎么用 sqlmap 跑 盲注", "sqlmap", ConceptRoleIdentity},
		{"tomcat 弱口令 怎么 打", "tomcat", ConceptRoleIdentity},
		{"mysql udf 提权 姿势", "mysql", ConceptRoleIdentity},
	} {
		plan, err := PlanQuery(tc.query)
		if err != nil {
			t.Fatalf("%q: %v", tc.query, err)
		}
		found := false
		for _, group := range plan.Groups {
			if group.ConceptID == tc.wantID && group.Role == tc.role {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q: concept %q not recognised as %s; groups = %#v",
				tc.query, tc.wantID, tc.role, plan.Groups)
		}
	}
}

// An alias that contains every token of a narrower alias in the same concept
// renders as a redundant OR branch, and FTS5 scores a row once per matching
// branch. That roughly doubles the best score for rows matching both, which
// tightens trimByRelevance's cutoff and silently shrinks the reported total.
// Measured before the guard existed: tomcat -7.07 -> -17.78, spring 3.13x.
func TestBuildConceptAliasIndex_RejectsSubsumedAlias(t *testing.T) {
	_, err := buildConceptAliasIndex([]SecurityConcept{
		{ID: "tomcat", Aliases: []string{"tomcat", "apache tomcat"}, Role: ConceptRoleIdentity},
	})
	if err == nil {
		t.Fatal("expected an error for an alias subsumed by a narrower alias")
	}
	if !strings.Contains(err.Error(), "subsumed") {
		t.Fatalf("error = %v, want it to name the subsumption", err)
	}
}

// The same check must not reject legitimate alias sets, or the registry would be
// impossible to extend. Distinct tokens and translations are both fine.
func TestBuildConceptAliasIndex_AcceptsDisjointAliases(t *testing.T) {
	for _, concept := range securityConcepts {
		if _, err := buildConceptAliasIndex([]SecurityConcept{concept}); err != nil {
			t.Fatalf("concept %q rejected: %v", concept.ID, err)
		}
	}
	_, err := buildConceptAliasIndex([]SecurityConcept{
		{ID: "sql_injection", Aliases: []string{"sql injection", "sqli", "sql注入"}, Role: ConceptRoleTopic},
	})
	if err != nil {
		t.Fatalf("disjoint aliases rejected: %v", err)
	}
}

// Aliases must stay distinct across concepts too, so one word never resolves to
// two different roles.
func TestBuildConceptAliasIndex_RejectsSharedAliasAcrossConcepts(t *testing.T) {
	_, err := buildConceptAliasIndex([]SecurityConcept{
		{ID: "a", Aliases: []string{"shared"}, Role: ConceptRoleIdentity},
		{ID: "b", Aliases: []string{"shared"}, Role: ConceptRoleTopic},
	})
	if err == nil {
		t.Fatal("expected an error for an alias shared by two concepts")
	}
}
