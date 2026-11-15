package storage

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// CorpusProfile describes how one imported corpus maps to the source-agnostic
// resource facets. Profiles are intentionally configurable: a new Nuclei YAML
// repository can add its own category-to-vuln_type map without changing the
// importer or the API.
type CorpusProfile struct {
	Origin    string            `yaml:"origin"`
	Format    string            `yaml:"format"`
	VulnTypes map[string]string `yaml:"vuln_types"`
}

type corpusProfileFile struct {
	Profiles map[string]CorpusProfile `yaml:"profiles"`
}

// CorpusProfiles is keyed by the internal corpus name (builtin, team, nuclei).
type CorpusProfiles map[string]CorpusProfile

func LoadCorpusProfiles(path string) (CorpusProfiles, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return CorpusProfiles{}, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return CorpusProfiles{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read corpus profiles: %w", err)
	}
	var file corpusProfileFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse corpus profiles: %w", err)
	}
	if file.Profiles == nil {
		return CorpusProfiles{}, nil
	}
	return CorpusProfiles(file.Profiles), nil
}

func (p CorpusProfiles) Get(name, fallbackOrigin, fallbackFormat string) CorpusProfile {
	profile, ok := p[name]
	if !ok {
		profile = CorpusProfile{}
	}
	if strings.TrimSpace(profile.Origin) == "" {
		profile.Origin = fallbackOrigin
	}
	if strings.TrimSpace(profile.Format) == "" {
		profile.Format = fallbackFormat
	}
	return profile
}
