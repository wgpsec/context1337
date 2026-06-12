package search

import "github.com/wgpsec/context1337/internal/tokenize"

// Tokenize delegates to the shared tokenize package.
func Tokenize(text string) []string {
	return tokenize.Tokenize(text)
}

// Tokenize2String returns space-joined tokens for FTS5 insertion.
func Tokenize2String(text string) string {
	return tokenize.TokenizeToString(text)
}
