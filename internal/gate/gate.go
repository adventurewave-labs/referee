// Package gate implements the two-axis gate decision algorithm (PRD §5.3,
// normative, complete). Policy assigns each tool one verb per axis; the gate
// evaluates: (1) capability, (2) integrity, (3) confidentiality,
// (4) clean-auto-approve, (5) default deny. A call must be clean on every
// axis the policy gates.
package gate

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/adventurewave-labs/referee/internal/caps"
	"github.com/adventurewave-labs/referee/internal/labels"
	"github.com/adventurewave-labs/referee/internal/policy"
	"github.com/adventurewave-labs/referee/internal/probe"
)

// Actions.
const (
	Approve   = "approve"
	Challenge = "challenge"
	Deny      = "deny"
)

// Decision is the gate's output; it becomes a receipt verbatim.
type Decision struct {
	Action    string   // approve | challenge | deny
	Rule      string   // the clause that fired, e.g. "integrity:require-trusted+tainted"
	Integrity string   // axis status: pass-any | not-detected | tainted | (verb+state)
	Conf      string   // axis status: normal | high | (verb+state)
	BlockIDs  []string // blocks whose matching influenced the decision
	Approver  string   // set when a challenge resolved
	Reason    string   // human-readable cause for receipts/why
}

// Gate evaluates calls.
type Gate struct {
	Policy     *policy.Policy
	Matcher    *labels.Matcher
	Classifier *labels.Classifier
	Probe      *probe.Probe     // nil => integrity probes fail closed (tainted)
	Now        func() time.Time // clock for token liveness; nil => time.Now
}

// Input is one tool call to evaluate.
type Input struct {
	TaskID string
	Tool   string
	Args   map[string]any
}

// Evaluate runs the normative algorithm. blocks is the session's shadow
// context; token is the task's capability token (may be nil).
func (g *Gate) Evaluate(in Input, token *caps.Token, blocks []labels.Block) Decision {
	argsJSON, _ := json.Marshal(in.Args)
	argText := string(argsJSON)

	matches := g.Matcher.Matches(argText, blocks)
	// JSON marshaling escapes <, >, & (\u003c, \u0026, ...), so a secret span
	// containing such a byte survives only in the raw value — the map pass
	// misses it at the escape seam. Match each argument's raw string form too
	// and union the hits (deduped by BlockID below).
	for _, v := range in.Args {
		matches = append(matches, g.Matcher.Matches(fmt.Sprintf("%v", v), blocks)...)
	}
	byID := map[string]labels.Block{}
	var matched []labels.Block
	var ids []string
	for _, m := range matches {
		if b, ok := byID[m.BlockID]; !ok {
			for _, blk := range blocks {
				if blk.ID == m.BlockID {
					b = blk
					break
				}
			}
			byID[m.BlockID] = b
			matched = append(matched, b)
			ids = append(ids, m.BlockID)
		}
	}

	containmentTaint := false
	propagatedHigh := false
	untrustedCount := 0
	var trustedBlocks, untrustedBlocks []labels.Block
	for _, b := range blocks {
		if b.Untrusted() {
			untrustedBlocks = append(untrustedBlocks, b)
			untrustedCount++
		} else {
			trustedBlocks = append(trustedBlocks, b)
		}
	}
	for _, b := range matched {
		if b.Untrusted() {
			containmentTaint = true
		}
		if b.High() {
			propagatedHigh = true
		}
	}
	// Rule-based classifier fills the gap only when propagation was silent.
	argHigh := g.Classifier.LooksHigh(argText)
	callHigh := propagatedHigh || argHigh
	callSens := labels.SensNormal
	if callHigh {
		callSens = labels.SensHigh
	}

	tool := g.Policy.ToolFor(in.Tool)
	d := Decision{}

	// -- Step 1: capability check -----------------------------------------
	now := time.Now
	if g.Now != nil {
		now = g.Now
	}
	// a token handed in may have outlived its TTL or been ended since it was
	// fetched: liveness is re-checked here, never assumed
	if token != nil && !token.Alive(now()) {
		token = nil
	}
	if token == nil {
		return deny("cap:token-missing", "no capability token for task (token missing, expired, or task ended)")
	}
	capGap := !token.CoversCall(in.Tool, func(arg string) string { return scopeValue(in.Args, arg) }, callSens)
	if capGap {
		// Cap gap. May challenge ONLY if the policy opts in per tool and the
		// approver allowlist is non-empty; any grant is task-scoped and
		// expires with the token (the challenge grant rides the same token).
		// The opt-in never skips the axes: integrity and confidentiality are
		// still evaluated below and a deny there wins over the challenge.
		if !(tool.CapGapChallenge && len(tool.Approvers) > 0) {
			return deny("cap:missing", fmt.Sprintf("no cap covers tool %q at sensitivity %s (cap gap; cap-gap-challenge not enabled)", in.Tool, callSens))
		}
	}

	// -- Step 2: integrity axis -------------------------------------------
	integrityVerb := tool.Integrity
	tainted := containmentTaint
	probeRan := false
	if !tainted && integrityVerb != policy.TrustAny && untrustedCount > 0 {
		// Containment found no taint but untrusted content exists in the
		// shadow context: the set-based influence probe decides (synchronously).
		probeRan = true
		if g.Probe == nil {
			tainted = true // no judge configured: fail closed
		} else {
			v := g.Probe.Check(nil, argText, untrustedBlocks, trustedBlocks, tool.SinkClass)
			tainted = v.Verdict != probe.Clean // anything but an explicit clean is taint
		}
	}
	switch {
	case integrityVerb == policy.RequireTrusted && tainted:
		d.Action, d.Rule = Deny, "integrity:require-trusted+tainted"
		d.Reason = "require-trusted has no human path: untrusted influence detected (containment or set-probe)"
	case integrityVerb == policy.ChallengeIfTainted && tainted:
		d.Action, d.Rule = Challenge, "integrity:challenge-if-tainted+tainted"
		d.Reason = "untrusted influence detected; sending to allowlisted approver"
	default:
		d.Action, d.Rule = Approve, "integrity:pass"
	}
	switch {
	case integrityVerb == policy.TrustAny:
		d.Integrity = "pass-any"
	case tainted:
		d.Integrity = "tainted"
	default:
		if probeRan {
			d.Integrity = "not-detected(probe)"
		} else {
			d.Integrity = "not-detected"
		}
	}

	// -- Step 3: confidentiality axis -------------------------------------
	confVerb := tool.Confidentiality
	high := callHigh
	var cAction, cRule string
	switch {
	case confVerb == policy.RequireNormal && high:
		cAction, cRule = Deny, "conf:require-normal+high"
	case confVerb == policy.ChallengeIfHigh && high:
		cAction, cRule = Challenge, "conf:challenge-if-high+high"
	default:
		cAction, cRule = Approve, "conf:pass"
	}
	if high {
		d.Conf = "high"
	} else {
		d.Conf = "normal"
	}

	// Strongest action wins; rules cite the firing clause in evaluation
	// order (capability > integrity > confidentiality). A deny always beats
	// a challenge: nothing goes to a human that policy would deny anyway.
	switch {
	case rank(cAction) > rank(d.Action):
		if d.Action == Approve {
			d.Rule = cRule
		} else {
			d.Rule = d.Rule + "+" + cRule
		}
		d.Action = cAction
		d.Reason = confReason(cAction, high)
	case rank(cAction) == rank(d.Action) && d.Action == Deny:
		d.Rule = d.Rule + "+" + cRule // both axes deny: record both clauses
	}

	// Opted-in cap gap: the call goes to a human unless an axis denies.
	if capGap {
		switch d.Action {
		case Approve:
			d.Action, d.Rule = Challenge, "cap-gap-challenge"
			d.Reason = "no cap covers this call; policy opted into approver challenge for cap gaps"
		case Challenge:
			d.Rule = "cap-gap-challenge+" + d.Rule
			d.Reason = "no cap covers this call (cap-gap challenge opted in); " + d.Reason
		}
		d.BlockIDs = ids
		sort.Strings(d.BlockIDs)
		return d
	}

	// -- Step 4: clean axes auto-approve -----------------------------------
	if d.Action == Approve {
		d.Action, d.Rule = Approve, "auto:clean("+d.Rule+","+cRule+")"
		d.Reason = "clean on every gated axis; auto-approved with receipt"
	}
	d.BlockIDs = ids
	sort.Strings(d.BlockIDs)
	return d
}

func deny(rule, reason string) Decision {
	return Decision{Action: Deny, Rule: rule, Reason: reason, Integrity: "unchecked", Conf: "unchecked"}
}

func rank(a string) int {
	switch a {
	case Deny:
		return 3
	case Challenge:
		return 2
	default:
		return 1
	}
}

func axisStatus(high bool) string {
	if high {
		return "high"
	}
	return "normal"
}

func confReason(action string, high bool) string {
	if action == Deny {
		return "high-sensitivity content movement denied by require-normal"
	}
	if action == Challenge {
		return "high-sensitivity content movement; sending to allowlisted approver"
	}
	return ""
}

func scopeValue(args map[string]any, key string) string {
	if key == "" {
		return ""
	}
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}
