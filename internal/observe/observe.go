// Package observe analyzes a receipt log against the policy that produced
// it and reports operational tuning evidence (PRD §12: cost profiler +
// auto-narrowing suggestions).
//
// The analyzer reads history, it does NOT rewrite policy files — suggestions
// are evidence for the operator, applied by hand through the normal
// policy-diff review flow (PRD: suggestions, not auto-remediation).
package observe

import (
	"fmt"
	"sort"
	"strings"

	"github.com/adventurewave-labs/referee/internal/policy"
	"github.com/adventurewave-labs/referee/internal/receipts"
)

// ToolStats is one tool's observed behavior.
type ToolStats struct {
	Tool       string
	Calls      int
	Approved   int
	Challenged int
	Denied     int
	// ProbeDecided counts decisions where the influence probe decided the
	// outcome (cost signal: each probe is an LLM call).
	ProbeDecided int
	// Rules records every distinct clause that fired, with counts.
	Rules map[string]int
	// CapGaps counts calls denied/challenged purely for missing caps.
	CapGaps int
}

// Report is the full analysis output.
type Report struct {
	Entries       int
	Tools         []ToolStats
	CapGaps       []ToolStats
	UnusedCaps    []string // task-class caps never exercised by any receipt
	AllCleanTools []string // 100% approve rate over ≥ MinCleanCalls calls
}

const MinCleanCalls = 5 // below this, "always clean" is not evidence

// Analyze replays a receipt log into per-tool statistics and tuning
// suggestions.
func Analyze(entries []receipts.Entry) Report {
	byTool := map[string]*ToolStats{}
	order := []string{}
	for _, e := range entries {
		ts, ok := byTool[e.Tool]
		if !ok {
			ts = &ToolStats{Tool: e.Tool, Rules: map[string]int{}}
			byTool[e.Tool] = ts
			order = append(order, e.Tool)
		}
		ts.Calls++
		switch e.Decision {
		case "approve":
			ts.Approved++
		case "challenge":
			ts.Challenged++
		case "deny":
			ts.Denied++
		}
		if strings.Contains(e.Axis, "probe") {
			ts.ProbeDecided++
		}
		if strings.Contains(e.Rule, "cap:") {
			ts.CapGaps++
		}
		ts.Rules[e.Rule]++
	}
	sort.Strings(order)
	var tools []ToolStats
	for _, name := range order {
		tools = append(tools, *byTool[name])
	}
	return Report{Entries: len(entries), Tools: tools}
}

// SuggestNarrowing derives auto-narrowing suggestions from the stats +
// policy (PRD §12: "suggest tighter caps from observed task traces"):
//
//   - ALL-CLEAN tools (≥ MinCleanCalls calls, 100% approve, no probe
//     decisions): candidates to TIGHTEN integrity verbs — the current
//     setting never fires.
//   - Cap-gap-heavy tools: candidates for explicit caps in the task class
//     (repeated cap:missing denials mean the operator's intent is unclear —
//     either grant the cap or accept the denials deliberately).
//   - NEVER-USED caps: granted caps no receipt ever exercised — candidates
//     for removal (least privilege decays without pruning).
func SuggestNarrowing(rep Report, pol *policy.Policy) []string {
	return SuggestNarrowingWithTasks(rep, pol, nil, nil)
}

// SuggestNarrowingWithTasks is SuggestNarrowing with task-class attribution:
// entries (the same receipts the report was built from) plus taskClasses
// (task-id → class). Unused-cap suggestions require the mapping.
func SuggestNarrowingWithTasks(rep Report, pol *policy.Policy, entries []receipts.Entry, taskClasses map[string]string) []string {
	var out []string
	for _, ts := range rep.Tools {
		if ts.Calls >= MinCleanCalls && ts.Approved == ts.Calls && ts.ProbeDecided == 0 {
			out = append(out, fmt.Sprintf(
				"TIGHTEN? %s: %d calls, all approved, probe never decided — integrity verb could tighten (challenge-if-tainted / require-trusted)", ts.Tool, ts.Calls))
		}
		if ts.CapGaps > 0 {
			out = append(out, fmt.Sprintf(
				"CAP GAP? %s: %d cap-missing denials — grant an explicit cap in the task class or accept the posture deliberately", ts.Tool, ts.CapGaps))
		}
	}
	// never-used caps: caps are granted PER TASK CLASS, so usage must be
	// attributed per class via taskClasses (task-id → class). Without the
	// mapping the analysis CANNOT know which class a call ran under — it
	// degrades honestly: no unused-cap suggestions, just a note (round-2
	// gate finding: a tool approved in one class must not hide unused
	// grants of it in every other).
	if taskClasses == nil {
		out = append(out, "INFO: unused-cap detection needs task-class attribution — pass taskClasses (task-id → class); skipping unused-cap suggestions")
		return out
	}
	exercised := map[string]map[string]bool{} // class → tool → approved?
	for _, ts := range rep.Tools {
		if ts.Approved == 0 {
			continue
		}
	}
	for _, e := range entries {
		class, ok := taskClasses[e.Task]
		if !ok {
			continue
		}
		if exercised[class] == nil {
			exercised[class] = map[string]bool{}
		}
		if e.Decision == "approve" {
			exercised[class][e.Tool] = true
		}
	}
	if pol != nil {
		for _, tc := range pol.Tasks {
			for _, c := range tc.Caps {
				if !exercised[tc.Class][c.Tool] {
					out = append(out, fmt.Sprintf(
						"UNUSED? task %s grants %s (pattern %s) — no APPROVED call exercised it in this class; prune or verify intent", tc.Class, c.Tool, c.Pattern))
				}
			}
		}
	}
	if len(out) == 0 {
		out = append(out, "no narrowing suggestions — the observed traces match the current policy shape")
	}
	return out
}
