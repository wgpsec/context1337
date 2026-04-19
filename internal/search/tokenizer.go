package search

import (
	"sort"
	"strings"
	"unicode"
)

// Tokenize splits text into search tokens using:
// 1. Security domain dictionary matching (longest match first)
// 2. English words: lowercase + split on non-alphanumeric
// 3. Remaining CJK: overlapping bigram windows
func Tokenize(text string) []string {
	if text == "" {
		return nil
	}

	text = strings.ToLower(text)
	var tokens []string
	seen := make(map[string]struct{})

	add := func(tok string) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			return
		}
		if _, ok := seen[tok]; !ok {
			seen[tok] = struct{}{}
			tokens = append(tokens, tok)
		}
	}

	// Phase 1: Extract dictionary matches (greedy longest-match)
	remaining := dictMatch(text, add)

	// Phase 2: Process remaining segments
	for _, seg := range remaining {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}

		var cjkBuf []rune
		var engBuf strings.Builder

		flushEng := func() {
			w := engBuf.String()
			engBuf.Reset()
			if w != "" {
				add(w)
			}
		}
		flushCJK := func() {
			if len(cjkBuf) == 0 {
				return
			}
			for i := 0; i < len(cjkBuf)-1; i++ {
				add(string(cjkBuf[i : i+2]))
			}
			if len(cjkBuf) == 1 {
				add(string(cjkBuf))
			}
			cjkBuf = cjkBuf[:0]
		}

		for _, r := range seg {
			if isCJK(r) {
				flushEng()
				cjkBuf = append(cjkBuf, r)
			} else if unicode.IsLetter(r) || unicode.IsDigit(r) {
				flushCJK()
				engBuf.WriteRune(r)
			} else {
				flushEng()
				flushCJK()
			}
		}
		flushEng()
		flushCJK()
	}

	return tokens
}

func dictMatch(text string, add func(string)) []string {
	sorted := make([]string, 0, len(SecurityTerms))
	for _, t := range SecurityTerms {
		sorted = append(sorted, strings.ToLower(t))
	}
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i]) > len(sorted[j])
	})

	type span struct{ start, end int }
	var matched []span

	lower := text
	for _, term := range sorted {
		idx := 0
		for {
			pos := strings.Index(lower[idx:], term)
			if pos < 0 {
				break
			}
			absPos := idx + pos
			end := absPos + len(term)
			overlaps := false
			for _, m := range matched {
				if absPos < m.end && end > m.start {
					overlaps = true
					break
				}
			}
			if !overlaps {
				matched = append(matched, span{absPos, end})
				add(term)
			}
			idx = absPos + len(term)
		}
	}

	sort.Slice(matched, func(i, j int) bool {
		return matched[i].start < matched[j].start
	})

	var remaining []string
	prev := 0
	for _, m := range matched {
		if m.start > prev {
			remaining = append(remaining, text[prev:m.start])
		}
		prev = m.end
	}
	if prev < len(text) {
		remaining = append(remaining, text[prev:])
	}

	return remaining
}

func isCJK(r rune) bool {
	return unicode.In(r,
		unicode.Han,
		unicode.Katakana,
		unicode.Hiragana,
		unicode.Hangul,
	)
}
