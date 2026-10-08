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

// A no-match retry must contain only concepts the planner recognised. Carrying
// an unrecognised word forward re-sends the term that made the query fail, which
// is why the older multi-topic retries hit zero of six offered.
func TestBuildNoMatchRetryQueries_DropsUnrecognisedWords(t *testing.T) {
	groups := planGroups(t, "sql注入 怎么 利用")
	retries := BuildNoMatchRetryQueries(groups, "skill")

	if len(retries) != 1 {
		t.Fatalf("retries = %#v, want one", retries)
	}
	if retries[0].Query != "sql注入" {
		t.Fatalf("retry query = %q, want the recognised topic alone", retries[0].Query)
	}
	if fmt.Sprint(retries[0].DroppedTerms) != "[怎么 利用]" {
		t.Fatalf("dropped terms = %v, want the unrecognised words", retries[0].DroppedTerms)
	}
	if retries[0].Type != "skill" {
		t.Fatalf("retry type = %q, want the caller's type filter preserved", retries[0].Type)
	}
}

// The single-topic shape an agent writes in prose: the older builder required
// two topics, so this produced no suggestion at all.
func TestBuildNoMatchRetryQueries_SingleTopicStillSuggests(t *testing.T) {
	groups := planGroups(t, "拿到 webshell 之后怎么提权")

	// The older builder is what this replaced; pin the gap it left.
	if old := BuildFocusedRetryQueries(groups, ""); len(old) != 1 {
		t.Fatalf("focused retries = %#v, want the spec-shaped allocation", old)
	}

	retries := BuildNoMatchRetryQueries(groups, "")
	if len(retries) != 1 {
		t.Fatalf("retries = %#v, want one", retries)
	}
	if retries[0].Query != "提权" {
		t.Fatalf("retry query = %q, want the recognised topic", retries[0].Query)
	}
	if fmt.Sprint(retries[0].DroppedTerms) != "[拿到 webshell 之后怎么]" {
		t.Fatalf("dropped terms = %v", retries[0].DroppedTerms)
	}
}

// Product identity must survive: a retry that loses "php" is about something
// else. This is the constraint the v2 closure design added role types for.
func TestBuildNoMatchRetryQueries_KeepsIdentity(t *testing.T) {
	groups := planGroups(t, "php 反序列化 怎么利用 服务器")
	retries := BuildNoMatchRetryQueries(groups, "skill")

	if len(retries) != 1 {
		t.Fatalf("retries = %#v, want one", retries)
	}
	if retries[0].Query != "php 反序列化" {
		t.Fatalf("retry query = %q, want identity plus topic", retries[0].Query)
	}
}

// Multi-topic: one retry per topic, so the caller stops being asked for both at
// once. The old gate would suppress this until two topics existed; now the same
// rule applies from the first topic.
func TestBuildNoMatchRetryQueries_OneRetryPerTopic(t *testing.T) {
	groups := planGroups(t, "php sql注入 提权")
	retries := BuildNoMatchRetryQueries(groups, "skill")

	got := make([]string, len(retries))
	for i, r := range retries {
		got[i] = r.Query
	}
	want := []string{"php sql注入", "php 提权"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("retries = %v, want %v", got, want)
	}
}

// A query with no recognised concept at all leaves nothing to narrow toward.
// Returning a retry here would mean guessing an identity from an unclassified
// word, which the closure design forbids.
//
// The example words have to be genuinely unrecognised. This case previously used
// "kerberoasting", which the registry now carries, so it would have been
// asserting the opposite of the property it names.
func TestBuildNoMatchRetryQueries_NoConceptsReturnsNothing(t *testing.T) {
	groups := planGroups(t, "zzzznothing 怎么 打")
	if retries := BuildNoMatchRetryQueries(groups, ""); len(retries) != 0 {
		t.Fatalf("retries = %#v, want none when the planner recognised nothing", retries)
	}
}

// Identities fill the focused-query budget, so there is no room for the topic
// that would make a retry narrower than the original query.
func TestBuildNoMatchRetryQueries_IdentityBudgetExhausted(t *testing.T) {
	groups := planGroups(t, "php java linux jwt sql注入 提权")
	if retries := BuildNoMatchRetryQueries(groups, "skill"); len(retries) != 0 {
		t.Fatalf("retries = %#v, want none once identities fill every slot", retries)
	}
}

// Every retry must be executable and deterministic: the caller will send it
// straight back to this same planner.
func TestBuildNoMatchRetryQueries_RetriesAreExecutableAndStable(t *testing.T) {
	for _, query := range []string{
		"sql注入 怎么 利用",
		"拿到 webshell 之后怎么提权",
		"php sql注入 提权",
		"php 反序列化 怎么利用 服务器",
	} {
		first := BuildNoMatchRetryQueries(planGroups(t, query), "skill")
		second := BuildNoMatchRetryQueries(planGroups(t, query), "skill")
		if fmt.Sprint(first) != fmt.Sprint(second) {
			t.Fatalf("%q: retries are not deterministic:\n%#v\n%#v", query, first, second)
		}
		for _, retry := range first {
			if _, err := PlanQuery(retry.Query); err != nil {
				t.Fatalf("%q produced unplannable retry %q: %v", query, retry.Query, err)
			}
		}
	}
}

// The dropped terms are per-retry copies. A caller that appends to one retry's
// list must not alter the others.
func TestBuildNoMatchRetryQueries_DroppedTermsAreIndependent(t *testing.T) {
	groups := planGroups(t, "php sql注入 提权 内网")
	retries := BuildNoMatchRetryQueries(groups, "skill")
	if len(retries) < 2 {
		t.Fatalf("retries = %#v, want at least two", retries)
	}
	retries[0].DroppedTerms = append(retries[0].DroppedTerms, "mutated")
	if fmt.Sprint(retries[1].DroppedTerms) != "[内网]" {
		t.Fatalf("second retry's dropped terms changed: %v", retries[1].DroppedTerms)
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
