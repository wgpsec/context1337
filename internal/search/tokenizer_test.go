package search

import (
	"testing"
)

func TestTokenize_English(t *testing.T) {
	tokens := Tokenize("SQL Injection attack on web server")
	want := []string{"sql injection", "attack", "on", "web", "server"}
	for _, w := range want {
		if !contains(tokens, w) {
			t.Errorf("Tokenize missing %q, got %v", w, tokens)
		}
	}
}

func TestTokenize_Chinese(t *testing.T) {
	tokens := Tokenize("跨站脚本攻击和SQL注入")
	if !contains(tokens, "跨站脚本攻击") {
		t.Errorf("missing dict term '跨站脚本攻击', got %v", tokens)
	}
	// SQL注入 should be matched as dict term "sql注入" or separately
	hasSQLRelated := contains(tokens, "sql injection") || contains(tokens, "sql") || contains(tokens, "注入")
	if !hasSQLRelated {
		t.Errorf("missing SQL-related token, got %v", tokens)
	}
}

func TestTokenize_CJKBigram(t *testing.T) {
	tokens := Tokenize("未知漏洞")
	// Either dict match or bigram
	hasBigram := contains(tokens, "未知") || contains(tokens, "知漏") || contains(tokens, "漏洞")
	if !hasBigram {
		t.Errorf("expected bigram or dict tokens for CJK, got %v", tokens)
	}
}

func TestTokenize_Mixed(t *testing.T) {
	tokens := Tokenize("使用Nmap进行端口扫描")
	if !contains(tokens, "nmap") {
		t.Errorf("missing 'nmap', got %v", tokens)
	}
	// "端口扫描" is a dictionary term; "扫描" alone may not appear
	if !contains(tokens, "端口扫描") && !contains(tokens, "扫描") {
		t.Errorf("missing '端口扫描' or '扫描', got %v", tokens)
	}
}

func TestTokenize_Empty(t *testing.T) {
	tokens := Tokenize("")
	if len(tokens) != 0 {
		t.Errorf("expected empty, got %v", tokens)
	}
}

func contains(tokens []string, s string) bool {
	for _, t := range tokens {
		if t == s {
			return true
		}
	}
	return false
}
