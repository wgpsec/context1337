package benchlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogger_WriteAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "calls.jsonl")

	logger, err := New(path, "test-scenario")
	if err != nil {
		t.Fatal(err)
	}

	logger.Log(Entry{
		Tool:          "search_skill",
		Input:         json.RawMessage(`{"query":"sql injection"}`),
		ResponseBytes: 1234,
		ResponseItems: 5,
		DurationMs:    12,
	})

	logger.Log(Entry{
		Tool:          "get_skill",
		Input:         json.RawMessage(`{"name":"sql-injection","depth":"full"}`),
		ResponseBytes: 5678,
		ResponseItems: 1,
		DurationMs:    8,
	})

	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	lines := splitNonEmpty(string(data))
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}

	var entry Record
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Scenario != "test-scenario" {
		t.Errorf("scenario = %q", entry.Scenario)
	}
	if entry.Tool != "search_skill" {
		t.Errorf("tool = %q", entry.Tool)
	}
	if entry.ResponseBytes != 1234 {
		t.Errorf("response_bytes = %d", entry.ResponseBytes)
	}
	if entry.Ts == "" {
		t.Error("ts is empty")
	}
}

func TestNilLogger(t *testing.T) {
	var logger *Logger
	// Must not panic
	logger.Log(Entry{Tool: "test"})
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
}

func splitNonEmpty(s string) []string {
	var result []string
	for _, line := range strings.Split(s, "\n") {
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}
