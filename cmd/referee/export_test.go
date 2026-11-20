package main

import (
	"strings"
	"testing"
)

// round-61: query-bearing SIEM endpoints are refused — the flag value sits
// in argv, where query-string credentials are process-listing visible.
func TestExportRefusesQueryBearingEndpoints(t *testing.T) {
	err := cmdExport([]string{"--endpoint", "https://siem.example/otlp?token=secret-token", "--log", "/nonexistent"})
	if err == nil {
		t.Fatalf("query-bearing endpoint must be refused")
	}
	if !strings.Contains(err.Error(), "REF_SIEM_AUTH") {
		t.Fatalf("refusal must point at the credential channel, got %v", err)
	}
}
