package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// round-79: task-class flag validation
func TestTaskClassMapValidation(t *testing.T) {
	m := taskClassMap{}
	if err := m.Set("task="); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty class must be rejected: %v", err)
	}
	if err := m.Set("=class"); err == nil || !strings.Contains(err.Error(), "task id") {
		t.Fatalf("empty task id must be rejected: %v", err)
	}
	if err := m.Set("noequals"); err == nil {
		t.Fatalf("missing = must be rejected")
	}
	if err := m.Set("task=real"); err != nil {
		t.Fatalf("valid pair rejected: %v", err)
	}
}

// round-81: conflicting duplicate mappings are rejected at Set time
func TestTaskClassMapConflictingDuplicates(t *testing.T) {
	m := taskClassMap{}
	if err := m.Set("task=ops"); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := m.Set("task=research"); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("conflicting duplicate must be rejected, got %v", err)
	}
	// identical re-declaration is a no-op
	if err := m.Set("task=ops"); err != nil {
		t.Fatalf("identical re-declaration must be a no-op, got %v", err)
	}
}

// round-75: --policy is validated even when the log is empty — operator
// input errors must not hide behind an early success return.
func TestObserveValidatesPolicyBeforeEmptyLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "empty.jsonl")
	os.WriteFile(logPath, nil, 0o600)
	badPolicy := filepath.Join(dir, "bad.yaml")
	os.WriteFile(badPolicy, []byte("version: 9\ntasks: []"), 0o600)

	err := cmdObserve([]string{"--log", logPath, "--policy", badPolicy})
	if err == nil || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("invalid policy must be reported even with an empty log, got %v", err)
	}
}
