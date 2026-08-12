package transliterate

import (
	"strings"
	"unicode"

	pinyin "github.com/mozillazg/go-pinyin"
)

// Pinyin converts a Han-only phrase to deterministic lowercase pinyin without
// tones or separators. Mixed text is deliberately rejected.
func Pinyin(text string) (string, bool) {
	runes := []rune(strings.TrimSpace(text))
	if len(runes) < 2 {
		return "", false
	}
	for _, r := range runes {
		if !unicode.Is(unicode.Han, r) {
			return "", false
		}
	}

	args := pinyin.NewArgs()
	args.Style = pinyin.Normal
	args.Heteronym = false
	args.Separator = ""
	converted := strings.ToLower(strings.Join(pinyin.LazyPinyin(string(runes), args), ""))
	if converted == "" || converted == strings.ToLower(string(runes)) {
		return "", false
	}
	return converted, true
}
