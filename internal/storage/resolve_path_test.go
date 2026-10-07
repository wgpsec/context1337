package storage

import (
	"path/filepath"
	"testing"
)

// The indexer writes paths relative to the resource root, but the runtime image
// only ships the data dir. If resolution regresses, get(depth=summary) silently
// loses the on-disk SKILL.md body and ref_total, and nuclei templates lose their
// raw YAML — all without an error, because every caller falls back to the DB.
func TestResolveResourcePath(t *testing.T) {
	cases := []struct {
		name     string
		dataDir  string
		filePath string
		want     string
	}{
		{"empty stays empty", "/app/data", "", ""},
		{"relative joins data dir", "/app/data", "skills/x/SKILL.md", "/app/data/skills/x/SKILL.md"},
		{"dict relative joins data dir", "/app/data", "Dic/auth/x.txt", "/app/data/Dic/auth/x.txt"},
		{"vuln relative joins data dir", "/app/data", "Vuln/a/b.md", "/app/data/Vuln/a/b.md"},
		// Nuclei rows are written by the loader at runtime and are already
		// absolute; joining them onto dataDir would produce a broken path.
		{"absolute passes through", "/app/data", "/app/data/nuclei-templates-rev/http/x.yaml", "/app/data/nuclei-templates-rev/http/x.yaml"},
		{"absolute outside data dir passes through", "/app/data", "/other/place/x.yaml", "/other/place/x.yaml"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveResourcePath(tc.dataDir, tc.filePath)
			if got != tc.want {
				t.Fatalf("ResolveResourcePath(%q, %q) = %q, want %q", tc.dataDir, tc.filePath, got, tc.want)
			}
		})
	}
}

// Both path conventions must survive a round trip through the same dataDir, so
// that an image built before the convention change keeps serving reads.
func TestResolveResourcePath_MixedConventionsCoexist(t *testing.T) {
	dataDir := "/app/data"
	relative := ResolveResourcePath(dataDir, "Vuln/middleware/jeecg/CVE-2023-1454.md")
	absolute := ResolveResourcePath(dataDir, "/build/machine/AboutSecurity/Vuln/x.md")

	if want := filepath.Join(dataDir, "Vuln/middleware/jeecg/CVE-2023-1454.md"); relative != want {
		t.Fatalf("relative = %q, want %q", relative, want)
	}
	if absolute != "/build/machine/AboutSecurity/Vuln/x.md" {
		t.Fatalf("absolute = %q, want it unchanged", absolute)
	}
}
