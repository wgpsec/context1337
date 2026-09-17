package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	AccessRead  = "read"
	AccessWrite = "write"

	SourceBuiltin = "builtin"
	SourceNuclei  = "nuclei"
	SourceTeam    = "team"
	SourceCustom  = "custom"

	BootstrapID = "bootstrap"
)

var allSources = []string{SourceBuiltin, SourceNuclei, SourceTeam, SourceCustom}

// Principal is an authenticated API key.
type Principal struct {
	ID       string
	Access   []string
	Sources  []string
	Granted  []string
	Origin   string
	canRead  bool
	canWrite bool
	allowed  map[string]struct{}
}

func AdminPrincipal(id string) Principal {
	if strings.TrimSpace(id) == "" {
		id = "anonymous"
	}
	return newPrincipal(id, []string{AccessRead, AccessWrite}, []string{SourceBuiltin, SourceTeam, SourceCustom})
}

func NewPrincipal(id string, access string, granted []string) Principal {
	items, err := parseAccessToken(access, true)
	if err != nil {
		items = nil
	}
	return newPrincipal(id, items, granted)
}

func newPrincipal(id string, access []string, granted []string) Principal {
	expanded := expandSources(granted)
	allowed := make(map[string]struct{}, len(expanded))
	for _, source := range expanded {
		allowed[source] = struct{}{}
	}
	canRead, canWrite := false, false
	for _, item := range access {
		switch item {
		case AccessRead:
			canRead = true
		case AccessWrite:
			canWrite = true
		}
	}
	return Principal{
		ID:       id,
		Access:   normalizeAccess(canRead, canWrite),
		Sources:  expanded,
		Granted:  append([]string(nil), granted...),
		canRead:  canRead,
		canWrite: canWrite,
		allowed:  allowed,
	}
}

func expandSources(granted []string) []string {
	seen := make(map[string]struct{}, len(allSources))
	var out []string
	add := func(source string) {
		if _, ok := seen[source]; ok {
			return
		}
		seen[source] = struct{}{}
		out = append(out, source)
	}
	for _, source := range granted {
		switch source {
		case SourceBuiltin:
			add(SourceBuiltin)

			add(SourceNuclei)
		case SourceNuclei, SourceTeam, SourceCustom:
			add(source)
		}
	}
	return out
}

func normalizeAccess(read, write bool) []string {
	var out []string
	if read {
		out = append(out, AccessRead)
	}
	if write {
		out = append(out, AccessWrite)
	}
	return out
}

func (p Principal) AllowsSource(source string) bool {
	if len(p.allowed) == 0 {
		return true
	}
	_, ok := p.allowed[source]
	return ok
}

func (p Principal) AllowsRead() bool {
	return p.canRead
}

func (p Principal) AllowsWrite() bool {
	return p.canWrite
}

func (p Principal) AllowsCustomWrite() bool {
	return p.AllowsWrite() && p.AllowsSource(SourceCustom)
}

func (p Principal) AllowsToggle(source string) bool {
	return p.AllowsWrite() && p.AllowsSource(source)
}

func parseAccessToken(value string, writeImpliesRead bool) ([]string, error) {
	switch strings.TrimSpace(value) {
	case AccessRead:
		return []string{AccessRead}, nil
	case AccessWrite:
		if writeImpliesRead {
			return []string{AccessRead, AccessWrite}, nil
		}
		return []string{AccessWrite}, nil
	default:
		return nil, fmt.Errorf("access must be read or write")
	}
}

func parseAccess(raw json.RawMessage) ([]string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fmt.Errorf("access is required")
	}
	if raw[0] == '"' {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, fmt.Errorf("access must be read or write")
		}
		return parseAccessToken(value, true)
	}
	var items []string
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("access must be read or write")
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("access is required")
	}
	seen := map[string]struct{}{}
	read, write := false, false
	for _, item := range items {
		item = strings.TrimSpace(item)
		switch item {
		case AccessRead:
			read = true
		case AccessWrite:
			write = true
		default:
			return nil, fmt.Errorf("access must be read or write")
		}
		if _, ok := seen[item]; ok {
			return nil, fmt.Errorf("duplicate access %q", item)
		}
		seen[item] = struct{}{}
	}
	return normalizeAccess(read, write), nil
}
