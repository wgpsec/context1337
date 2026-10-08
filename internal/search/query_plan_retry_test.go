package search

import (
	"fmt"
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
func TestBuildNoMatchRetryQueries_NoConceptsReturnsNothing(t *testing.T) {
	groups := planGroups(t, "kerberoasting 怎么 打")
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
