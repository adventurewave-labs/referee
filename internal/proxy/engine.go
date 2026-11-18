package proxy

import (
	"encoding/json"
	"fmt"
	"log"

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
	Log        *log.Logger                     // stderr logger; never logs args or secrets
}

// HandleToolCall runs the §5.3 pipeline for one tools/call. It returns the
// MCP result to hand the agent and whether the upstream server must be
// called. Denied calls never reach upstream.
func (e *Engine) HandleToolCall(sess *Session, params ToolCallParams) (ToolCallResult, bool, error) {
	tool := e.Policy.ToolFor(params.Name)
	taskID := sess.TaskID
	token := e.Caps.Get(taskID)
	blocks := sess.Snapshot()

	argsJSON, _ := json.Marshal(params.Arguments)
	d := e.Gate.Evaluate(gate.Input{TaskID: sess.TaskID, Tool: params.Name, Args: params.Arguments}, token, blocks)

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

	e.receipt(sess, params, d, string(argsJSON))

	switch d.Action {
	case gate.Approve:
		return ToolCallResult{}, true, nil
	case gate.Challenge:
		// challenge approved: forward (grant is task-scoped and dies with the token)
		return ToolCallResult{}, true, nil
	default:
		return DenyResult(d.Action, d.Rule, d.Reason), false, nil
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

func (e *Engine) receipt(sess *Session, params ToolCallParams, d gate.Decision, argsJSON string) {
	if e.Receipts == nil {
		return
	}
	axis := fmt.Sprintf("integrity=%s conf=%s", d.Integrity, d.Conf)
	_, _, err := e.Receipts.Append(receipts.Record{
		Task:          sess.TaskID,
		Tool:          params.Name,
		Rule:          d.Rule,
		Decision:      d.Action,
		Approver:      d.Approver,
		BlockIDs:      d.BlockIDs,
		Axis:          axis,
		ArgsCanonical: argsJSON, // stored only as keyed HMAC
	})
	if err != nil && e.Log != nil {
		e.Log.Printf("receipts: append failed: %v", err)
	}
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
