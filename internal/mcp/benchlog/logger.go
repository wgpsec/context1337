package benchlog

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Entry is what callers pass to Log.
type Entry struct {
	Tool          string          `json:"tool"`
	Input         json.RawMessage `json:"input"`
	ResponseBytes int             `json:"response_bytes"`
	ResponseItems int             `json:"response_items"`
	DurationMs    int64           `json:"duration_ms"`
}

// Record is what gets written to the JSONL file (Entry + metadata).
type Record struct {
	Ts            string          `json:"ts"`
	Scenario      string          `json:"scenario"`
	Tool          string          `json:"tool"`
	Input         json.RawMessage `json:"input"`
	ResponseBytes int             `json:"response_bytes"`
	ResponseItems int             `json:"response_items"`
	DurationMs    int64           `json:"duration_ms"`
}

// Logger writes benchmark records to a JSONL file.
// A nil *Logger is safe to use (all methods are no-ops).
type Logger struct {
	mu       sync.Mutex
	file     *os.File
	enc      *json.Encoder
	scenario string
}

// New creates a Logger that appends to the given file path.
// The parent directory must exist.
func New(path, scenario string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &Logger{
		file:     f,
		enc:      json.NewEncoder(f),
		scenario: scenario,
	}, nil
}

// Log writes a single entry. Safe for concurrent use. No-op on nil receiver.
func (l *Logger) Log(e Entry) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enc.Encode(Record{
		Ts:            time.Now().UTC().Format(time.RFC3339Nano),
		Scenario:      l.scenario,
		Tool:          e.Tool,
		Input:         e.Input,
		ResponseBytes: e.ResponseBytes,
		ResponseItems: e.ResponseItems,
		DurationMs:    e.DurationMs,
	})
}

// Close flushes and closes the file. No-op on nil receiver.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	return l.file.Close()
}
