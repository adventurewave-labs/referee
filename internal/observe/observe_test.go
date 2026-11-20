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
	sugg := SuggestNarrowingWithTasks(rep, pol, entries, map[string]string{"t": "ops"})
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

// gate finding: a cap:missing DENIAL must not mark the tool as exercising
// its caps — the denial demonstrates no cap was exercised.
func TestSuggestNarrowingDeniedCallsNotExercised(t *testing.T) {
	f := &policy.File{
		Version: 1,
		Tasks: []policy.TaskClass{{
			Class: "ops",
			Caps:  []policy.CapDecl{{Tool: "denied_tool", Pattern: "**"}},
		}},
	}
	pol, _ := policy.Compile(f)
	entries := []receipts.Entry{
		entry(1, "denied_tool", "cap:missing", "deny", "unchecked"),
		entry(2, "denied_tool", "cap:missing", "deny", "unchecked"),
	}
	rep := Analyze(entries)
	joined := strings.Join(SuggestNarrowingWithTasks(rep, pol, entries, map[string]string{"t": "ops"}), "\n")
	if !strings.Contains(joined, "UNUSED? task ops grants denied_tool") {
		t.Fatalf("denied-only tool must still be flagged unused: %s", joined)
	}
}

// multiple grants sharing one tool: approval of the tool exercises ALL its
// caps in v1 (scope-level tracking is future work) — but a tool with zero
// approvals stays unused even when OTHER tools were approved.
func TestSuggestNarrowingSharedToolGrants(t *testing.T) {
	f := &policy.File{
		Version: 1,
		Tasks: []policy.TaskClass{{
			Class: "ops",
			Caps: []policy.CapDecl{
				{Tool: "shared_tool", Pattern: "/a/**"},
				{Tool: "shared_tool", Pattern: "/b/**"},
				{Tool: "idle_tool", Pattern: "**"},
			},
		}},
	}
	pol, _ := policy.Compile(f)
	entries := []receipts.Entry{
		entry(1, "shared_tool", "auto:clean", "approve", "integrity=pass conf=pass"),
	}
	rep := Analyze(entries)
	joined := strings.Join(SuggestNarrowingWithTasks(rep, pol, entries, map[string]string{"t": "ops"}), "\n")
	if strings.Contains(joined, "grants shared_tool") {
		t.Fatalf("approved tool must not be flagged unused: %s", joined)
	}
	if !strings.Contains(joined, "grants idle_tool") {
		t.Fatalf("idle tool must be flagged: %s", joined)
	}
}

// round-2: without task-class attribution the analysis degrades honestly —
// no unused-cap suggestions, just the INFO note.
func TestAbsentTaskClassesDegrades(t *testing.T) {
	f := &policy.File{
		Version: 1,
		Tasks: []policy.TaskClass{{
			Class: "ops",
			Caps:  []policy.CapDecl{{Tool: "never_called_tool", Pattern: "**"}},
		}},
	}
	pol, _ := policy.Compile(f)
	entries := []receipts.Entry{
		entry(1, "other", "auto:clean", "approve", "integrity=pass conf=pass"),
	}
	rep := Analyze(entries)
	sugg := SuggestNarrowingWithTasks(rep, pol, entries, nil)
	joined := strings.Join(sugg, "\n")
	if strings.Contains(joined, "UNUSED?") {
		t.Fatalf("no attribution = no unused-cap suggestions (would be per-class wrong): %s", joined)
	}
	if !strings.Contains(joined, "task-class attribution") {
		t.Fatalf("the INFO note must explain the degradation: %s", joined)
	}
}

// round-2: per-class attribution — a tool approved under research does NOT
// exercise its deploy-class grant.
func TestPerClassAttribution(t *testing.T) {
	f := &policy.File{
		Version: 1,
		Tasks: []policy.TaskClass{
			{Class: "research", Caps: []policy.CapDecl{{Tool: "shared", Pattern: "**"}}},
			{Class: "deploy", Caps: []policy.CapDecl{{Tool: "shared", Pattern: "**"}}},
		},
	}
	pol, _ := policy.Compile(f)
	entries := []receipts.Entry{
		{Seq: 1, TS: time.Unix(1_700_000_000, 0).UTC(), Task: "t-research", Tool: "shared",
			Rule: "auto:clean", Decision: "approve", ArgsHMAC: "h", PrevHash: "p", Hash: "x"},
	}
	rep := Analyze(entries)
	sugg := SuggestNarrowingWithTasks(rep, pol, entries, map[string]string{"t-research": "research", "t-deploy": "deploy"})
	joined := strings.Join(sugg, "\n")
	if strings.Contains(joined, "task research grants shared") {
		t.Fatalf("research-approved grant must not be flagged unused")
	}
	if !strings.Contains(joined, "task deploy grants shared") {
		t.Fatalf("deploy-class grant of a research-only tool must be flagged unused: %s", joined)
	}
}
