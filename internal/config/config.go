package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultMCPSessionTimeout closes an idle MCP session after 30 minutes. The
// handler keeps one session per client handshake, so leaving sessions open
// forever makes memory grow with total traffic instead of concurrency.
const DefaultMCPSessionTimeout = 30 * time.Minute

type Config struct {
	Port              int
	DataDir           string
	BuiltinDB         string
	RuntimeDB         string
	TeamDir           string
	APIKey            string
	APIKeysFile       string
	AdminKey          string
	NucleiDir         string
	NucleiMinSeverity string
	MCPSessionTimeout time.Duration
}

func Load() (*Config, error) {
	port := 1337
	if v := os.Getenv("ABOUTSECURITY_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %w", err)
		}
		port = p
	}

	dataDir := envOrDefault("ABOUTSECURITY_DATA_DIR", "./data")
	nucleiDir := os.Getenv("NUCLEI_TEMPLATES_DIR")
	nucleiMinSeverity := os.Getenv("NUCLEI_MIN_SEVERITY")
	mcpSessionTimeout, err := parseMCPSessionTimeout(os.Getenv("ABOUTSECURITY_MCP_SESSION_TIMEOUT"))
	if err != nil {
		return nil, err
	}

	return &Config{
		Port:              port,
		DataDir:           dataDir,
		BuiltinDB:         dataDir + "/builtin.db",
		RuntimeDB:         dataDir + "/runtime/runtime.db",
		TeamDir:           dataDir + "/team",
		APIKey:            os.Getenv("ABOUTSECURITY_API_KEY"),
		APIKeysFile:       os.Getenv("ABOUTSECURITY_API_KEYS_FILE"),
		AdminKey:          os.Getenv("ABOUTSECURITY_ADMIN_KEY"),
		NucleiDir:         nucleiDir,
		NucleiMinSeverity: nucleiMinSeverity,
		MCPSessionTimeout: mcpSessionTimeout,
	}, nil
}

// parseMCPSessionTimeout accepts a Go duration (>=1m). "off" and zero values
// disable the timeout, which is useful for tests and as an escape hatch.
func parseMCPSessionTimeout(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultMCPSessionTimeout, nil
	}
	if strings.EqualFold(raw, "off") {
		return 0, nil
	}
	timeout, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid ABOUTSECURITY_MCP_SESSION_TIMEOUT %q: %w", raw, err)
	}
	if timeout == 0 {
		return 0, nil
	}
	if timeout < time.Minute {
		return 0, fmt.Errorf("ABOUTSECURITY_MCP_SESSION_TIMEOUT must be at least 1m, or 0/off to disable (got %s)", timeout)
	}
	return timeout, nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
