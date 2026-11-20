package main

import (
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
