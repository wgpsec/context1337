package search

import "github.com/Esonhugh/context1337/internal/tokenize"

// Tokenize delegates to the shared tokenize package.
func Tokenize(text string) []string {
	return tokenize.Tokenize(text)
}
