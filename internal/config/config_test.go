package config

import (
	"os"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	// Clear env
	os.Unsetenv("ABOUTSECURITY_PORT")
	os.Unsetenv("ABOUTSECURITY_DATA_DIR")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Port != 1337 {
		t.Errorf("Port = %d, want 1337", cfg.Port)
	}
	if cfg.DataDir != "./data" {
		t.Errorf("DataDir = %q, want ./data", cfg.DataDir)
	}
}

func TestLoad_CustomPort(t *testing.T) {
	os.Setenv("ABOUTSECURITY_PORT", "9090")
	defer os.Unsetenv("ABOUTSECURITY_PORT")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Port != 9090 {
		t.Errorf("Port = %d, want 9090", cfg.Port)
	}
}

func TestLoad_InvalidPort(t *testing.T) {
	os.Setenv("ABOUTSECURITY_PORT", "notanumber")
	defer os.Unsetenv("ABOUTSECURITY_PORT")

	_, err := Load()
	if err == nil {
		t.Error("expected error for invalid port")
	}
}
