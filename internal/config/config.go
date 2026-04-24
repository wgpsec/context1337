package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Port      int
	DataDir   string
	BuiltinDB string
	RuntimeDB string
	TeamDir   string
	APIKey string
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

	return &Config{
		Port:      port,
		DataDir:   dataDir,
		BuiltinDB: dataDir + "/builtin.db",
		RuntimeDB: dataDir + "/runtime/runtime.db",
		TeamDir:   dataDir + "/team",
		APIKey: os.Getenv("ABOUTSECURITY_API_KEY"),
	}, nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
