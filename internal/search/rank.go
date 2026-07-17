package search

import (
	"sort"
	"strings"
	"unicode"
)

func rankCandidates(plan QueryPlan, results []SearchResult) {
	sort.SliceStable(results, func(i, j int) bool {
		leftAnchors := anchorNameHits(plan, results[i].Name)
		rightAnchors := anchorNameHits(plan, results[j].Name)
		if leftAnchors != rightAnchors {
			return leftAnchors > rightAnchors
		}
		leftNameHits := nameGroupHits(plan, results[i].Name)
		rightNameHits := nameGroupHits(plan, results[j].Name)
		if leftNameHits != rightNameHits {
			return leftNameHits > rightNameHits
		}
		leftIdentityHits := nameAndTagGroupHits(plan, results[i])
		rightIdentityHits := nameAndTagGroupHits(plan, results[j])
		if leftIdentityHits != rightIdentityHits {
			return leftIdentityHits > rightIdentityHits
		}
		if results[i].Score != results[j].Score {
			return results[i].Score < results[j].Score
		}
		return StableID(results[i].Resource) < StableID(results[j].Resource)
	})
}

func nameAndTagGroupHits(plan QueryPlan, result SearchResult) int {
	identity := result.Name + " " + result.Tags
	hits := 0
	for _, group := range plan.Groups {
		if textMatchesAnyAlias(identity, group.Alternatives) {
			hits++
		}
	}
	return hits
}

func nameGroupHits(plan QueryPlan, name string) int {
	hits := 0
	for _, group := range plan.Groups {
		if textMatchesAnyAlias(name, group.Alternatives) {
			hits++
		}
	}
	return hits
}

func anchorNameHits(plan QueryPlan, name string) int {
	hits := 0
	for _, group := range plan.Groups {
		if group.Anchor && textMatchesAnyAlias(name, group.Alternatives) {
			hits++
		}
	}
	return hits
}

func textMatchesAnyAlias(text string, aliases []string) bool {
	normalized := normalizeSearchText(text)
	for _, alias := range aliases {
		needle := normalizeSearchText(alias)
		if needle != "" && strings.Contains(" "+normalized+" ", " "+needle+" ") {
			return true
		}
	}
	return false
}

func normalizeSearchText(value string) string {
	value = strings.ToLower(value)
	value = strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return ' '
	}, value)
	return strings.Join(strings.Fields(value), " ")
}
