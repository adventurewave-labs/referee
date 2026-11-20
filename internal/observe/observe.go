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
		// cap gap = the MISSING-CAP clause on a deny/challenge (round-74/75):
		// exact rule equality — prefix matching would pull in unrelated
		// rules like cap:missing-resolved; approved calls are not gaps
		if (e.Decision == "deny" || e.Decision == "challenge") &&
			e.Rule == "cap:missing" {
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
	return SuggestNarrowingWithTasks(rep, pol, nil, nil, "")
}

// SuggestNarrowingWithTasks is SuggestNarrowing with task-class attribution:
// entries (the same receipts the report was built from), taskClasses
// (task-id → class), and policyHash (the SHA-256 of the policy THAT PRODUCED
// the receipts — grants of a different policy must never be pruned on this
// analysis).
func SuggestNarrowingWithTasks(rep Report, pol *policy.Policy, entries []receipts.Entry, taskClasses map[string]string, policyHash string) []string {
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
	// Attribution must be COMPLETE: a nil/empty map, no mapped approved
	// receipts, or approved receipts whose task is absent from the map all
	// make "unused" conclusions unsupportable — an approved call of unknown
	// class may have exercised ANY grant (round-N gate finding).
	// Attributability is about MAPPING, not existence: denied/challenged
	// receipts carry the same class information as approvals (a class that
	// denies everything still proves its grants went unused — round-74).
	// Only receipts whose class is UNKNOWN are non-attributable.
	mappedDecisions, unknownDecisions := 0, 0
	for _, e := range entries {
		if cls, ok := taskClasses[e.Task]; ok && cls != "" {
			mappedDecisions++
			continue
		}
		unknownDecisions++
	}
	// task-class VALUES must exist in the policy: a typo'd class would hide
	// real usage and recommend pruning in-use grants (round-79)
	knownClasses := map[string]bool{}
	if pol != nil {
		for _, tc := range pol.Tasks {
			knownClasses[tc.Class] = true
		}
	}
	unknownClasses := map[string]bool{}
	for _, cls := range taskClasses {
		if cls != "" && pol != nil && !knownClasses[cls] {
			unknownClasses[cls] = true
		}
	}
	if len(unknownClasses) > 0 {
		names := make([]string, 0, len(unknownClasses))
		for c := range unknownClasses {
			names = append(names, `"`+c+`"`)
		}
		sort.Strings(names)
		out = append(out, fmt.Sprintf(
			"INFO: task-class attribution references classes not in the policy: %s — fix the mapping; skipping unused-cap suggestions", strings.Join(names, ", ")))
		return out
	}
	if taskClasses == nil || len(taskClasses) == 0 || mappedDecisions == 0 || unknownDecisions > 0 {
		out = append(out, fmt.Sprintf(
			"INFO: unused-cap detection needs COMPLETE task-class attribution — %d decision(s) have unmapped tasks; pass taskClasses (task-id → class) covering every receipt; skipping unused-cap suggestions", unknownDecisions))
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
		if class == "" {
			continue // empty class values never attribute usage (round-78)
		}
		if exercised[class] == nil {
			exercised[class] = map[string]bool{}
		}
		if e.Decision == "approve" {
			exercised[class][e.Tool] = true
		}
	}
	// Grant-specific (prune) suggestions require a POLICY BINDING when the
	// caller asks for one (policyHash non-empty — the CLI always passes the
	// loaded policy's hash): the receipts must carry the same hash. A log
	// from policy A analyzed against policy B would recommend pruning B's
	// grants based on A's traffic (round-77). policyHash == "" is the
	// caller's explicit opt-in to an unbound analysis (unit tests).
	if pol != nil && policyHash != "" {
		bound := true
		for _, e := range entries {
			if e.PolicyHash == "" {
				bound = false // pre-binding log: grants can't be proven to match
				continue
			}
			if e.PolicyHash != policyHash {
				short := e.PolicyHash
				if len(short) > 12 {
					short = short[:12]
				}
				out = append(out, fmt.Sprintf("INFO: receipt log was produced by a DIFFERENT policy (hash %s ≠ this policy) — grant-specific suggestions suppressed", short))
				bound = false
				break
			}
		}
		if !bound {
			out = append(out, "INFO: grant-specific (prune) suggestions suppressed — the log is not bound to this policy")
			pol = nil // suppress the grant walk below
		}
	}
	if pol != nil {
		// usage is tracked per (class, tool) — caps are distinguished by
		// tool AND pattern, so per-pattern unused detection needs the call's
		// scope value, which receipts don't record (they HMAC args). v1
		// therefore flags a (class, tool) grant as unused only when NO
		// approved call for that tool exists in the class; per-pattern
		// narrowing within a used tool requires scope attribution (future:
		// record the effective scope on the receipt).
		for _, tc := range pol.Tasks {
			for _, c := range tc.Caps {
				if !exercised[tc.Class][c.Tool] {
					out = append(out, fmt.Sprintf(
						"UNUSED? task %s grants %s (pattern %s) — no APPROVED call exercised this tool in this class; per-pattern pruning needs scope attribution on receipts (future)", tc.Class, c.Tool, c.Pattern))
				}
			}
		}
	}
	if len(out) == 0 {
		out = append(out, "no narrowing suggestions — the observed traces match the current policy shape")
	}
	return out
}
