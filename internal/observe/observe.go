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
	// never-used caps: walk the policy's task-class caps, check which
	// tools the receipts actually exercised
	exercised := map[string]bool{}
	for _, ts := range rep.Tools {
		exercised[ts.Tool] = true
	}
	if pol != nil {
		for _, tc := range pol.Tasks {
			for _, c := range tc.Caps {
				if !exercised[c.Tool] {
					out = append(out, fmt.Sprintf(
						"UNUSED? task %s grants %s (pattern %s) — no receipt exercised it; prune or verify intent", tc.Class, c.Tool, c.Pattern))
				}
			}
		}
	}
	if len(out) == 0 {
		out = append(out, "no narrowing suggestions — the observed traces match the current policy shape")
	}
	return out
}
