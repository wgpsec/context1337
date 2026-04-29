package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"critical", 4},
		{"CRITICAL", 4},
		{"high", 3},
		{"HIGH", 3},
		{"medium", 2},
		{"low", 1},
		{"info", 0},
		{"", 0},
	}
	for _, tc := range tests {
		got := severityRank(tc.input)
		if got != tc.expected {
			t.Errorf("severityRank(%q) = %d, want %d", tc.input, got, tc.expected)
		}
	}
}

func TestScanNucleiVulns(t *testing.T) {
	tmpDir := t.TempDir()
	cvesDir := filepath.Join(tmpDir, "http", "cves", "2022")
	if err := os.MkdirAll(cvesDir, 0o755); err != nil {
		t.Fatal(err)
	}

	highYAML := `id: CVE-2022-0824
info:
  name: Webmin RCE
  severity: high
  description: Webmin before 1.990 allows RCE.
  tags: webmin,rce
  metadata:
    vendor: webmin
    product: webmin
`
	mediumYAML := `id: CVE-2022-9999
info:
  name: Some Medium CVE
  severity: medium
  description: A medium severity vulnerability.
  tags: example,test
  metadata:
    vendor: acme
    product: widget
`
	nonCVEYAML := `id: panel-detect
info:
  name: Panel Detection
  severity: high
  description: Detects admin panels.
  tags: panel
`

	writeFile := func(name, content string) {
		if err := os.WriteFile(filepath.Join(cvesDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("CVE-2022-0824.yaml", highYAML)
	writeFile("CVE-2022-9999.yaml", mediumYAML)
	writeFile("panel-detect.yaml", nonCVEYAML)

	t.Run("minSeverity=high returns 1 result", func(t *testing.T) {
		results, err := ScanNucleiVulns(tmpDir, "high")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		v := results[0]
		if v.ID != "CVE-2022-0824" {
			t.Errorf("ID = %q, want CVE-2022-0824", v.ID)
		}
		if v.Severity != "HIGH" {
			t.Errorf("Severity = %q, want HIGH", v.Severity)
		}
		if v.Category != "nuclei-cve" {
			t.Errorf("Category = %q, want nuclei-cve", v.Category)
		}
		if v.Tags != "webmin,rce" {
			t.Errorf("Tags = %q, want webmin,rce", v.Tags)
		}
	})

	t.Run("minSeverity=medium returns 2 results", func(t *testing.T) {
		results, err := ScanNucleiVulns(tmpDir, "medium")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("expected 2 results, got %d", len(results))
		}
	})

	t.Run("minSeverity=empty defaults to high, returns 1 result", func(t *testing.T) {
		results, err := ScanNucleiVulns(tmpDir, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 result (same as high), got %d", len(results))
		}
		if results[0].ID != "CVE-2022-0824" {
			t.Errorf("ID = %q, want CVE-2022-0824", results[0].ID)
		}
	})
}
