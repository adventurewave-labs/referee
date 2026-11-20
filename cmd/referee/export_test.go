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

// round-63: userinfo (user:token@host) is argv-visible too — refused with
// the same credential-channel guidance.
func TestExportRefusesUserinfoEndpoints(t *testing.T) {
	err := cmdExport([]string{"--endpoint", "https://user:secret-token@siem.example/otlp", "--log", "/nonexistent"})
	if err == nil {
		t.Fatalf("userinfo endpoint must be refused")
	}
	if !strings.Contains(err.Error(), "REF_SIEM_AUTH") {
		t.Fatalf("refusal must point at the credential channel, got %v", err)
	}
}
