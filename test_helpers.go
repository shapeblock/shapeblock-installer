package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSetup provides common test setup functionality
type TestSetup struct {
	TempDir string
	t       *testing.T
}

func NewTestSetup(t *testing.T) *TestSetup {
	tempDir, err := os.MkdirTemp("", "shapeblock-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	return &TestSetup{
		TempDir: tempDir,
		t:       t,
	}
}

func (ts *TestSetup) Cleanup() {
	if err := os.RemoveAll(ts.TempDir); err != nil {
		ts.t.Errorf("Failed to cleanup temp dir: %v", err)
	}
}

// CreateTempFile creates a temporary file with given content
func (ts *TestSetup) CreateTempFile(name, content string) string {
	path := filepath.Join(ts.TempDir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		ts.t.Fatalf("Failed to create temp file: %v", err)
	}
	return path
}
