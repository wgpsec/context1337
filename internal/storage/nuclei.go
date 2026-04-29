package storage

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type nucleiInfo struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string `yaml:"name"`
		Severity    string `yaml:"severity"`
		Description string `yaml:"description"`
		Tags        string `yaml:"tags"`
		Metadata    struct {
			Vendor  string `yaml:"vendor"`
			Product string `yaml:"product"`
		} `yaml:"metadata"`
	} `yaml:"info"`
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// ScanNucleiVulns walks nucleiDir/http/cves/ and returns CVE entries at or above minSeverity.
// If minSeverity is empty, it defaults to "high".
func ScanNucleiVulns(nucleiDir, minSeverity string) ([]VulnData, error) {
	if minSeverity == "" {
		minSeverity = "high"
	}
	minRank := severityRank(minSeverity)

	cvesDir := filepath.Join(nucleiDir, "http", "cves")
	var vulns []VulnData

	err := filepath.WalkDir(cvesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		name := d.Name()
		if !strings.HasPrefix(name, "CVE-") || !strings.HasSuffix(name, ".yaml") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil // skip unreadable files
		}

		var tmpl nucleiInfo
		if err := yaml.Unmarshal(data, &tmpl); err != nil || tmpl.ID == "" {
			return nil // skip unparseable or empty-ID templates
		}

		if severityRank(tmpl.Info.Severity) < minRank {
			return nil
		}

		vulns = append(vulns, VulnData{
			ID:          tmpl.ID,
			Title:       tmpl.Info.Name,
			Description: tmpl.Info.Description,
			Severity:    strings.ToUpper(tmpl.Info.Severity),
			Tags:        tmpl.Info.Tags,
			Vendor:      tmpl.Info.Metadata.Vendor,
			Product:     tmpl.Info.Metadata.Product,
			Category:    "nuclei-cve",
			Body:        tmpl.Info.Description,
			FilePath:    path,
		})
		return nil
	})

	return vulns, err
}
