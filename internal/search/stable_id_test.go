package search

import (
	"strings"
	"testing"
)

func TestStableID(t *testing.T) {
	r := Resource{Source: "builtin", Type: "dict", Name: "Auth/password/Top100.txt"}
	got := StableID(r)
	want := "absec://builtin/dict/Auth%2Fpassword%2FTop100.txt"
	if got != want {
		t.Fatalf("StableID() = %q, want %q", got, want)
	}
}

func TestParseStableID(t *testing.T) {
	source, typ, key, err := ParseStableID("absec://nuclei/vuln/CVE-2021-44228")
	if err != nil {
		t.Fatalf("ParseStableID: %v", err)
	}
	if source != "nuclei" || typ != "vuln" || key != "CVE-2021-44228" {
		t.Fatalf("parsed = (%q, %q, %q), want (nuclei, vuln, CVE-2021-44228)", source, typ, key)
	}
}

func TestParseStableID_EscapedPath(t *testing.T) {
	source, typ, key, err := ParseStableID("absec://builtin/payload/XSS%2Fevents.txt")
	if err != nil {
		t.Fatalf("ParseStableID: %v", err)
	}
	if source != "builtin" || typ != "payload" || key != "XSS/events.txt" {
		t.Fatalf("parsed = (%q, %q, %q), want (builtin, payload, XSS/events.txt)", source, typ, key)
	}
}

func TestParseStableID_Invalid(t *testing.T) {
	tests := []string{
		"",
		"context1337://builtin/skill/sql-injection",
		"absec://builtin/skill",
		"absec://builtin/tool/nmap",
		"absec:///skill/sql-injection",
		"absec://builtin/skill/",
		"absec://builtin/dict/Auth/password/Top100.txt",
		"absec://builtin/dict/%zz",
	}
	for _, id := range tests {
		t.Run(id, func(t *testing.T) {
			_, _, _, err := ParseStableID(id)
			if err == nil {
				t.Fatalf("expected error for %q", id)
			}
		})
	}
}

func TestGetByStableID_SourceCollision(t *testing.T) {
	db := setupTestDB(t)
	for _, source := range []string{"builtin", "nuclei"} {
		if err := InsertResource(db, Resource{
			Type:        "vuln",
			Name:        "CVE-2021-44228",
			Source:      source,
			FilePath:    source + "/log4j.md",
			Category:    "middleware",
			Description: source + " log4j",
			Body:        source + " body",
		}); err != nil {
			t.Fatal(err)
		}
	}

	r, err := GetByStableID(db, "absec://nuclei/vuln/CVE-2021-44228")
	if err != nil {
		t.Fatalf("GetByStableID: %v", err)
	}
	if r == nil {
		t.Fatal("expected resource")
	}
	if r.Source != "nuclei" {
		t.Fatalf("Source = %q, want nuclei", r.Source)
	}
}

func TestGetByStableID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	r, err := GetByStableID(db, "absec://builtin/skill/missing")
	if err != nil {
		t.Fatalf("GetByStableID: %v", err)
	}
	if r != nil {
		t.Fatalf("resource = %#v, want nil", r)
	}
}

func TestGetByStableID_InvalidID(t *testing.T) {
	db := setupTestDB(t)
	_, err := GetByStableID(db, "not-an-absec-id")
	if err == nil {
		t.Fatal("expected invalid ID error")
	}
	if !strings.Contains(err.Error(), "invalid resource id") {
		t.Fatalf("error = %q, want invalid resource id", err.Error())
	}
}
