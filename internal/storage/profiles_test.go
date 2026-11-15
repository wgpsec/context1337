package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCorpusProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.yaml")
	if err := os.WriteFile(path, []byte(`
profiles:
  team:
    origin: private
    format: markdown
  nuclei:
    origin: nuclei-official
    format: nuclei-yaml
    vuln_types:
      cves: cve
      cnvd: cnvd
`), 0o600); err != nil {
		t.Fatalf("write profiles: %v", err)
	}
	profiles, err := LoadCorpusProfiles(path)
	if err != nil {
		t.Fatalf("load profiles: %v", err)
	}
	team := profiles.Get("team", "platform", "unknown")
	if team.Origin != "private" || team.Format != "markdown" {
		t.Fatalf("team profile = %#v", team)
	}
	nuclei := profiles.Get("nuclei", "platform", "unknown")
	if nuclei.Origin != "nuclei-official" || nuclei.VulnTypes["cves"] != "cve" {
		t.Fatalf("nuclei profile = %#v", nuclei)
	}
	fallback := profiles.Get("missing", "platform", "markdown")
	if fallback.Origin != "platform" || fallback.Format != "markdown" {
		t.Fatalf("fallback profile = %#v", fallback)
	}
}

func TestLoadCorpusProfilesMissingFile(t *testing.T) {
	profiles, err := LoadCorpusProfiles(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatalf("load missing profiles: %v", err)
	}
	if len(profiles) != 0 {
		t.Fatalf("profiles = %#v, want empty", profiles)
	}
}
