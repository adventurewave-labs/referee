package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"fmt"
	"log"
	"sort"

	"github.com/adventurewave-labs/referee/internal/caps"
	"github.com/adventurewave-labs/referee/internal/challenge"
	"github.com/adventurewave-labs/referee/internal/gate"
	"github.com/adventurewave-labs/referee/internal/labels"
	"github.com/adventurewave-labs/referee/internal/policy"
	"github.com/adventurewave-labs/referee/internal/receipts"
)

// Engine is the shared interception pipeline both transports use.
type Engine struct {
	Policy     *policy.Policy
	Gate       *gate.Gate
	Caps       *caps.Store
	Receipts   *receipts.Log
	Challenges *challenge.Manager
	Notifier   func(challenge.Challenge) error // dispatches the redacted challenge
	ReceiptKey []byte                          // key for block HMAC refs in challenges
	PolicyHash string                          // sha256 of the active policy — stamped on receipts so observe binds analysis to the producing policy
	Log        *log.Logger                     // stderr logger; never logs args or secrets
	// ControlToken authenticates the privileged control RPCs (task_start,
	// user_block) that mint caps or add trusted content. They share the
	// agent's stream, so they are refused unless the operator-side harness
	// proves itself with this token; empty disables them entirely.
	ControlToken []byte
}

// HandleToolCall runs the §5.3 pipeline for one tools/call. It returns the
// MCP result to hand the agent, the SANITIZED arguments as raw JSON (nil
// when the arguments were not rewritten — transports must forward the
// ORIGINAL request bytes then: re-decoding drops unknown fields and
// perturbs large integers), whether the upstream server must be called,
// and an error. Denied calls never reach upstream.
func (e *Engine) HandleToolCall(sess *Session, params ToolCallParams) (ToolCallResult, json.RawMessage, bool, error) {
	tool := e.Policy.ToolFor(params.Name)
	taskID := sess.TaskID
	token := e.Caps.Get(taskID)
	blocks := sess.Snapshot()

	argsJSON, _ := json.Marshal(params.Arguments)
	effective := json.RawMessage(nil) // what the transport must forward upstream
	d := e.Gate.Evaluate(gate.Input{TaskID: sess.TaskID, Tool: params.Name, Args: params.Arguments}, token, blocks)

	// Redaction path (PRD §6 P1): where policy allows (tool redact:
	// strip|mask), a tainted/high decision gets ONE re-gate over sanitized
	// arguments. If the sanitized call clears every gated axis it forwards
	// with the redacted arguments — the upstream tool never sees the tainted
	// segments. Denials from the capability axis are not redactable, and a
	// call that still fails the re-gate keeps its original decision.
	mode := labels.RedactMode(tool.Redact)
	switch mode {
	case labels.RedactStrip, labels.RedactMask:
		// known sanitize modes
	default:
		mode = labels.RedactNone // none, empty, and UNKNOWN modes never redact — unknown must not default to mask
	}
	if mode != labels.RedactNone &&
		(d.Action == gate.Challenge || d.Action == gate.Deny) &&
		(strings.Contains(d.Rule, "tainted") || strings.HasPrefix(d.Rule, "conf:")) {
		matched := blocksForIDs(blocks, d.BlockIDs)
		var sanitizedArgs json.RawMessage // non-nil ONLY when redaction rewrote the args
		if sanitized, changed := sanitizeArgs(params.Arguments, matched, mode, e.Gate.Classifier); changed {
			d2 := e.Gate.Evaluate(gate.Input{TaskID: sess.TaskID, Tool: params.Name, Args: sanitized}, token, blocks)
			if d2.Action == gate.Approve {
				// the transport forwards FULL tool-call params: name stays,
				// arguments are the sanitized ones. Marshal BEFORE switching
				// the decision — a marshal failure must keep the original
				// challenge/deny, never forward unsanitized arguments under a
				// redact:* approval (round-32 finding).
				full := ToolCallParams{Name: params.Name, Arguments: sanitized}
				fullJSON, mErr := json.Marshal(full)
				if mErr != nil {
					d.Reason = "sanitized arguments could not be encoded; keeping the original decision: " + mErr.Error()
					d.Rule += "+redact:marshal-failed"
				} else {
					origRule := d.Rule
					d = d2
					d.Rule = "redact:" + string(mode) + "+" + origRule
					d.Reason = "arguments auto-sanitized (" + string(mode) + "); re-gated clean on every axis; upstream receives the redacted arguments"
					sanitizedArgs = fullJSON
					// the receipt HMACs the ARGUMENTS MAP alone — the same
					// canonical form every other receipt uses (round-33: the
					// {name,arguments} wrapper made redacted digests
					// inconsistent with the rest of the log)
					ab, _ := json.Marshal(sanitized)
					argsJSON = ab
					// write the sanitized values back into the shared arguments
					// map (in-process consumers see the sanitized view)
					for k, v := range sanitized {
						params.Arguments[k] = v
					}
				}
			}
		}
		if sanitizedArgs != nil {
			effective = sanitizedArgs
		}
	}

	if d.Action == gate.Challenge {
		// The gate sends to a human: no challenge flow configured => fail closed.
		if e.Challenges == nil {
			d.Action = gate.Deny
			d.Rule = "challenge:no-flow"
			d.Reason = "challenge required but no challenge flow configured; denying (fail closed)"
		} else {
			// Redacted challenge (§5.4): shapes only; attacker text clearly marked.
			red := challenge.Redact(params.Name, params.Arguments, blocksForIDs(blocks, d.BlockIDs), e.Gate.Classifier, e.ReceiptKey)
			res, ch, err := e.Challenges.Request(sess.TaskID, params.Name, d.Rule, red, tool.Approvers, e.Notifier)
			if err != nil {
				// dispatch failure (e.g. Slack unreachable): fail closed
				d.Action = gate.Deny
				d.Rule = "challenge:notify-failed"
				d.Reason = "challenge could not be dispatched: " + err.Error()
			} else {
				decision, approver, rule := res.ReceiptFields(ch)
				d.Action = decision
				d.Rule = rule
				d.Approver = approver
				d.Reason = res.Reason
				// the challenge blocked: the task may have ended or its TTL
				// lapsed meanwhile — an approval never outlives the token
				if d.Action != gate.Deny && !tokenStillLive(e, taskID, token) {
					d.Action = gate.Deny
					d.Rule += "+cap:token-dead"
					d.Reason = "approved, but the task token died while the challenge was pending (task end or TTL); denying"
				}
			}
		}
	}

	// The gate blocks synchronously (influence probe, challenge wait): the
	// token may expire or be revoked DURING the decision. An approval never
	// outlives the token it was gated with — recheck after every blocking
	// authorization operation, not just challenges (round-13, P1-4).
	if d.Action != gate.Deny && !tokenStillLive(e, taskID, token) {
		d.Action = gate.Deny
		d.Rule += "+cap:token-dead-after-gate"
		d.Reason = "the task token died while the gate was deciding (probe/challenge block, task end, or TTL); denying"
	}

	// no receipt, no call: a decision that cannot be recorded never forwards
	if err := e.receipt(taskID, params, d, string(argsJSON)); err != nil {
		if e.Log != nil {
			e.Log.Printf("receipts: append failed, denying %s: %v", params.Name, err)
		}
		return DenyResult(gate.Deny, "receipt:write-failed", "the decision receipt could not be written; denying (fail closed)"), nil, false, nil
	}

	switch d.Action {
	case gate.Approve:
		return ToolCallResult{}, effective, true, nil
	case gate.Challenge:
		// challenge approved: forward (grant is task-scoped and dies with the token)
		return ToolCallResult{}, effective, true, nil
	default:
		return DenyResult(d.Action, d.Rule, d.Reason), nil, false, nil
	}
}

// tokenStillLive reports whether the task's token is still the live one the
// call was gated with (not ended, not expired, not replaced).
func tokenStillLive(e *Engine, taskID string, gated *caps.Token) bool {
	cur := e.Caps.Get(taskID)
	return gated != nil && cur == gated
}

// IngestResult captures an upstream tools/call result into the shadow
// context with per-source labeling.
func (e *Engine) IngestResult(sess *Session, params ToolCallParams, resultRaw json.RawMessage) {
	tool := e.Policy.ToolFor(params.Name)
	text := TextFromResult(resultRaw)
	if text == "" {
		return
	}
	path := ""
	if tool.EmitPathArg != "" {
		if v, ok := params.Arguments[tool.EmitPathArg].(string); ok {
			path = v
		}
	}
	sess.IngestToolResult(tool, path, text)
}

// receipt appends the decision to the receipt chain. A nil Receipts log
// (library embedding without receipts) records nothing.
func (e *Engine) receipt(taskID string, params ToolCallParams, d gate.Decision, argsJSON string) error {
	if e.Receipts == nil {
		return nil
	}
	// Tool names are agent-controlled: an undeclared tool's name could BE the
	// secret (an agent invents {"sk-live-...": "x"} as a tool name to exfil
	// via the receipt log). Undeclared names are recorded HMAC-referenced only.
	toolName := params.Name
	if _, declared := e.Policy.Tools[params.Name]; !declared {
		toolName = "undeclared:" + hex.EncodeToString(nameHMAC(e.ReceiptKey, params.Name))[:12]
	}
	axis := fmt.Sprintf("integrity=%s conf=%s", d.Integrity, d.Conf)
	_, _, err := e.Receipts.Append(receipts.Record{
		Task:          taskID,
		Tool:          toolName,
		Rule:          d.Rule,
		Decision:      d.Action,
		Approver:      d.Approver,
		BlockIDs:      d.BlockIDs,
		Axis:          axis,
		ArgsCanonical: argsJSON, // stored only as keyed HMAC
		PolicyHash:    e.PolicyHash,
	})
	return err
}

func blocksForIDs(blocks []labels.Block, ids []string) []labels.Block {
	if len(ids) == 0 {
		return nil
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []labels.Block
	for _, b := range blocks {
		if want[b.ID] {
			out = append(out, b)
		}
	}
	return out
}

// Control handlers shared by both transports (referee/* JSON-RPC methods).

// StartTask mints a capability token from the operator's policy; the harness
// manifest may only narrow (§5.2).
func (e *Engine) StartTask(sess *Session, taskID, class string, requestedCaps []string, operatorContext string) error {
	if taskID == "" {
		taskID = sess.ID
	}
	capsList, err := e.Policy.NarrowCaps(class, requestedCaps)
	if err != nil {
		return err
	}
	var cs []caps.Cap
	for _, c := range capsList {
		cs = append(cs, caps.Cap{Tool: c.Tool, ScopeArg: c.ScopeArg, Pattern: c.Pattern, Sensitivity: c.Sensitivity})
	}
	ttl := e.Policy.Defaults.TTL.D()
	if tc, ok := e.Policy.Tasks[class]; ok && tc.TTL.D() > 0 {
		ttl = tc.TTL.D()
	}
	tok, err := e.Caps.Mint(taskID, class, ttl, e.Policy.Defaults.TTLCeiling.D(), cs...)
	if err != nil {
		return err
	}
	sess.TaskID = taskID
	sess.TaskClass = class
	if operatorContext != "" {
		sess.AddOperator(operatorContext)
	}
	if e.Log != nil {
		note := ""
		if tok.Clamped {
			note = " (clamped to ttl ceiling)"
		}
		e.Log.Printf("task %s (%s) started: %d caps%s", taskID, class, len(cs), note)
	}
	return nil
}

// EndTask revokes the task token immediately (§5.2: no grace window).
func (e *Engine) EndTask(sess *Session) bool {
	killed := e.Caps.End(sess.TaskID)
	if e.Log != nil && killed {
		e.Log.Printf("task %s ended: token revoked immediately", sess.TaskID)
	}
	return killed
}

// IngestUpstream labels every text-bearing payload the upstream sends the
// agent outside a gated tools/call — tool descriptions (the classic
// tool-poisoning vector), resources/read, prompts/get, initialize
// instructions — as untrusted. Upstream-controlled content never enters the
// shadow context unlabeled: the integrity axis must not fail open on
// transport shape (round-2 finding #2).
func (e *Engine) IngestUpstream(sess *Session, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return
	}
	for _, text := range collectPayloadText(v, 0) {
		sess.AddBlock("upstream", labels.TrustUntrusted, labels.SensNormal, text)
	}
}

// IngestResponse labels a full upstream response: its result payload AND its
// error object — an upstream error message is as upstream-controlled as any
// tool result and must not reach the agent unlabeled (round-5 finding).
func (e *Engine) IngestResponse(sess *Session, resp *Response) {
	if resp == nil {
		return
	}
	e.IngestUpstream(sess, resp.Result)
	if resp.Error != nil {
		if b, err := json.Marshal(resp.Error); err == nil {
			e.IngestUpstream(sess, b)
		}
	}
}

// collectPayloadText gathers strings under the text-bearing keys of an
// upstream payload, bounded in depth.
func collectPayloadText(v any, depth int) []string {
	if depth > 12 {
		return nil
	}
	switch t := v.(type) {
	case map[string]any:
		var out []string
		for k, val := range t {
			if k == "structuredContent" {
				// MCP structuredContent IS content: every string leaf in its
				// subtree is upstream-controlled text (bounded)
				out = append(out, collectAllStrings(val, depth+1)...)
				continue
			}
			if s, ok := val.(string); ok && len(s) > 0 && knownTextKey(k) {
				out = append(out, s)
				continue
			}
			out = append(out, collectPayloadText(val, depth+1)...)
		}
		return out
	case []any:
		var out []string
		for _, item := range t {
			out = append(out, collectPayloadText(item, depth+1)...)
		}
		return out
	}
	return nil
}

// knownTextKey names the payload keys that carry agent-visible prose.
func knownTextKey(k string) bool {
	switch k {
	case "text", "description", "instructions", "message", "data":
		return true
	}
	return false
}

// collectAllStrings gathers every string leaf of a structured subtree,
// bounded in count so a hostile payload cannot flood the shadow context.
func collectAllStrings(v any, depth int) []string {
	if depth > 12 {
		return nil
	}
	switch t := v.(type) {
	case string:
		if len(t) > 0 {
			return []string{t}
		}
	case []any:
		var out []string
		for _, item := range t {
			out = append(out, collectAllStrings(item, depth+1)...)
			if len(out) >= 64 {
				return out[:64]
			}
		}
		return out
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var out []string
		for _, k := range keys {
			out = append(out, collectAllStrings(t[k], depth+1)...)
			if len(out) >= 64 {
				return out[:64]
			}
		}
		return out
	}
	return nil
}

// nameHMAC is the keyed HMAC used for undeclared-tool name references in
// receipts (same key family as challenge block refs).
func nameHMAC(key []byte, name string) []byte {
	if len(key) == 0 {
		key = []byte("referee-unnamed")
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("tool-name|" + name))
	return m.Sum(nil)
}

// sanitizeArgs applies labels.RedactValue to every string argument value
// against the blocks the containment matcher flagged; non-string arguments
// pass through untouched.
func sanitizeArgs(args map[string]any, matched []labels.Block, mode labels.RedactMode, classifier *labels.Classifier) (map[string]any, bool) {
	changed := false
	out := make(map[string]any, len(args))
	for k, v := range args {
		str, ok := v.(string)
		if !ok {
			out[k] = v
			continue
		}
		clean, ch := labels.RedactValue(str, matched, mode, classifier, 12)
		if ch {
			changed = true
		}
		out[k] = clean
	}
	return out, changed
}
