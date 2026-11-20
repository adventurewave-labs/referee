package observe

import (
	"strings"
	"testing"
	"time"

	"github.com/adventurewave-labs/referee/internal/policy"
	"github.com/adventurewave-labs/referee/internal/receipts"
)

func entry(seq int, tool, rule, decision, axis string) receipts.Entry {
	return receipts.Entry{Seq: uint64(seq), TS: time.Unix(1_700_000_000, 0).UTC(),
		Task: "t", Tool: tool, Rule: rule, Decision: decision, Axis: axis,
		ArgsHMAC: "h", PrevHash: "p", Hash: "x"}
}

func TestAnalyzeTallies(t *testing.T) {
	entries := []receipts.Entry{
		entry(1, "web.fetch", "auto:clean(i,conf)", "approve", "integrity=not-detected conf=normal"),
		entry(2, "web.fetch", "auto:clean(i,conf)", "approve", "integrity=not-detected(probe) conf=normal"),
		entry(3, "send_email", "integrity:challenge-if-tainted+tainted", "challenge", "integrity=tainted conf=normal"),
		entry(4, "undeclared", "cap:missing", "deny", "integrity=unchecked conf=unchecked"),
	}
	rep := Analyze(entries)
	if rep.Entries != 4 || len(rep.Tools) != 3 {
		t.Fatalf("tally wrong: %+v", rep)
	}
	byTool := map[string]ToolStats{}
	for _, ts := range rep.Tools {
		byTool[ts.Tool] = ts
	}
	wf := byTool["web.fetch"]
	if wf.Calls != 2 || wf.Approved != 2 || wf.ProbeDecided != 1 {
		t.Fatalf("web.fetch stats wrong: %+v", wf)
	}
	if byTool["undeclared"].CapGaps != 1 {
		t.Fatalf("cap gaps not counted")
	}
	if byTool["send_email"].Challenged != 1 {
		t.Fatalf("challenge not counted")
	}
}

func TestSuggestNarrowingAllClean(t *testing.T) {
	var entries []receipts.Entry
	for i := 0; i < 8; i++ {
		entries = append(entries, entry(i+1, "summarize", "auto:clean", "approve",
			"integrity=not-detected conf=normal"))
	}
	rep := Analyze(entries)
	sugg := SuggestNarrowing(rep, nil)
	joined := strings.Join(sugg, "\n")
	if !strings.Contains(joined, "TIGHTEN? summarize") {
		t.Fatalf("all-clean tool must yield a tighten suggestion: %s", joined)
	}
}

func TestSuggestNarrowingCapGaps(t *testing.T) {
	entries := []receipts.Entry{
		entry(1, "mystery", "cap:missing", "deny", "unchecked"),
		entry(2, "mystery", "cap:missing", "deny", "unchecked"),
	}
	rep := Analyze(entries)
	sugg := SuggestNarrowing(rep, nil)
	if !strings.Contains(strings.Join(sugg, "\n"), "CAP GAP? mystery") {
		t.Fatalf("cap-gap suggestion missing: %v", sugg)
	}
}

func TestSuggestNarrowingUnusedCaps(t *testing.T) {
	f := &policy.File{
		Version: 1,
		Tasks: []policy.TaskClass{{
			Class: "ops",
			Caps: []policy.CapDecl{
				{Tool: "never_called_tool", Pattern: "**"},
				{Tool: "called_tool", Pattern: "**"},
			},
		}},
	}
	pol, err := policy.Compile(f)
	if err != nil {
		t.Fatal(err)
	}
	entries := []receipts.Entry{
		entry(1, "called_tool", "auto:clean", "approve", "integrity=pass conf=pass"),
	}
	rep := Analyze(entries)
	sugg := SuggestNarrowing(rep, pol)
	joined := strings.Join(sugg, "\n")
	if !strings.Contains(joined, "UNUSED? task ops grants never_called_tool") {
		t.Fatalf("unused-cap suggestion missing: %s", joined)
	}
	if strings.Contains(joined, "UNUSED? task ops grants called_tool") {
		t.Fatalf("exercised tool must not be flagged unused: %s", joined)
	}
}

func TestMinCleanCallsGuard(t *testing.T) {
	// 2 calls all approved: below MinCleanCalls → no tighten suggestion
	entries := []receipts.Entry{
		entry(1, "quiet_tool", "auto:clean", "approve", "integrity=pass conf=pass"),
		entry(2, "quiet_tool", "auto:clean", "approve", "integrity=pass conf=pass"),
	}
	rep := Analyze(entries)
	for _, s := range SuggestNarrowing(rep, nil) {
		if strings.Contains(s, "TIGHTEN? quiet_tool") {
			t.Fatalf("sub-threshold tool must not be suggested: %s", s)
		}
	}
}
