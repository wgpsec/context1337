package transliterate

import "testing"

func TestPinyinConvertsHanPhraseWithoutToneOrSeparator(t *testing.T) {
	got, ok := Pinyin("天擎")
	if !ok || got != "tianqing" {
		t.Fatalf("Pinyin(天擎) = %q, %v", got, ok)
	}
}

func TestPinyinRejectsSingleHanAndMixedText(t *testing.T) {
	for _, value := range []string{"天", "v2天擎", "天擎/api"} {
		if got, ok := Pinyin(value); ok {
			t.Fatalf("Pinyin(%q) = %q, true; want rejected", value, got)
		}
	}
}
