package mcp

import (
	"testing"
)

func TestNewMCPServer_Instructions_LiteMode(t *testing.T) {
	db := setupUnifiedTest(t).DB
	dir := t.TempDir()

	_ = NewMCPServer(db, dir, ToolModeLite)
	_ = NewMCPServer(db, dir, ToolModeFull)
}
