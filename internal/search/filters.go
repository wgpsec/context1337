package search

import (
	"fmt"
	"strings"
)

// NormalizeSeverity canonicalises a vulnerability severity filter. Every
// bundled source stores severity in upper case, but callers do not reliably
// match that convention (LLM agents frequently send "critical"), so the search
// boundary normalises instead of making the caller guess.
func NormalizeSeverity(severity string) string {
	return strings.ToUpper(strings.TrimSpace(severity))
}

var productSeparators = strings.NewReplacer(
	"-", " ",
	"_", " ",
	"/", " ",
	".", " ",
)

// NormalizeProduct reduces a product filter to the token form used by
// ProductMatchExpression. Product names are free-form across sources: builtin
// and team author `weblogic`, while nuclei templates carry `weblogic_server`.
// Matching therefore ignores case, separator style and token order rather than
// demanding one spelling.
func NormalizeProduct(product string) string {
	normalized := productSeparators.Replace(strings.ToLower(strings.TrimSpace(product)))
	return strings.Join(strings.Fields(normalized), " ")
}

func normalizeSearchQuery(q SearchQuery) SearchQuery {
	q.Severity = NormalizeSeverity(q.Severity)
	q.Product = NormalizeProduct(q.Product)
	return q
}

func normalizeListQuery(q ListQuery) ListQuery {
	q.Severity = NormalizeSeverity(q.Severity)
	q.Product = NormalizeProduct(q.Product)
	return q
}

// ProductMatchExpression builds a SQL predicate that matches a normalised
// product filter (bound twice) against the normalised form of column. The
// comparison is token-aware: "weblogic" matches both "weblogic" and
// "weblogic server", but never matches inside a larger token ("web" does not
// match "weblogic").
//
// The SQL normalisation mirrors NormalizeProduct for the slug-shaped values the
// corpora store; it intentionally does not collapse repeated spaces because no
// source emits them.
func ProductMatchExpression(column string) string {
	normalized := fmt.Sprintf(
		"LOWER(REPLACE(REPLACE(REPLACE(REPLACE(%s, '-', ' '), '_', ' '), '/', ' '), '.', ' '))",
		column,
	)
	return fmt.Sprintf(
		"(INSTR(' ' || %s || ' ', ' ' || ? || ' ') > 0 OR INSTR(' ' || ? || ' ', ' ' || %s || ' ') > 0)",
		normalized, normalized,
	)
}
