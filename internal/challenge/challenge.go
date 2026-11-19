// Package challenge implements the human-in-the-loop flow (PRD §5.4/§9):
// challenges are redacted by construction — tool name, argument shapes with
// secret-bearing segments masked, HMAC references to involved blocks, and
// clearly-marked hostile excerpts of untrusted blocks. Approvals are
// authenticated AND authorized: the approver must be on that tool's allowlist
// from the policy DSL. Timeout is default-deny.
package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/adventurewave-labs/referee/internal/labels"
	"github.com/adventurewave-labs/referee/internal/receipts"
)

// RedactedArg is one argument's safe shape.
type RedactedArg struct {
	Name  string `json:"name"`
	Shape string `json:"shape"` // masked value + type annotation
}

// BlockRef is an HMAC reference to an involved block.
type BlockRef struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	HMAC   string `json:"hmac"` // short HMAC of block text under the receipt key
}

// Redacted is the full challenge payload — safe for Slack by construction.
type Redacted struct {
	Tool            string        `json:"tool"`
	Args            []RedactedArg `json:"args"`
	Blocks          []BlockRef    `json:"blocks"`
	HostileExcerpts []string      `json:"hostile_excerpts"` // attacker text, clearly marked
}

// Challenge is a pending human decision.
type Challenge struct {
	ID       string    `json:"id"`
	TaskID   string    `json:"task_id"`
	Tool     string    `json:"tool"`
	Rule     string    `json:"rule"`
	Redacted *Redacted `json:"redacted"`
	Created  time.Time `json:"created"`
	Deadline time.Time `json:"deadline"`
}

// Result is the resolution.
type Result struct {
	Approved bool
	Approver string
	TimedOut bool
	Reason   string
}

// Manager tracks pending challenges with timeout-default-deny.
type Manager struct {
	timeout    time.Duration
	now        func() time.Time
	receiptKey []byte // for block HMAC refs

	mu      sync.Mutex
	pending map[string]*pending
	counter int
}

type pending struct {
	ch      Challenge
	decided chan Result
	allow   map[string]bool
}

// NewManager creates the manager. timeout is the challenge deadline; on
// expiry the request is denied (default-deny) with reason challenge-timeout.
func NewManager(timeout time.Duration, receiptKey []byte, now func() time.Time) *Manager {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	if now == nil {
		now = time.Now
	}
	return &Manager{timeout: timeout, now: now, receiptKey: receiptKey, pending: map[string]*pending{}}
}

// Request creates a challenge, dispatches it to the notifier, and blocks
// until an allowlisted approver resolves it or the deadline passes (deny).
// The gate blocks synchronously by design (PRD §5.1).
func (m *Manager) Request(taskID, tool, rule string, red *Redacted, allowlist []string, notify func(Challenge) error) (Result, Challenge, error) {
	m.mu.Lock()
	m.counter++
	c := Challenge{
		ID:       fmt.Sprintf("ch-%06d", m.counter),
		TaskID:   taskID,
		Tool:     tool,
		Rule:     rule,
		Redacted: red,
		Created:  m.now(),
		Deadline: m.now().Add(m.timeout),
	}
	allow := map[string]bool{}
	for _, a := range allowlist {
		allow[a] = true
	}
	p := &pending{ch: c, decided: make(chan Result, 1), allow: allow}
	m.pending[c.ID] = p
	m.mu.Unlock()

	if notify != nil {
		if err := notify(c); err != nil {
			m.resolveInternal(c.ID, Result{Approved: false, Reason: "notify-failed: " + err.Error()})
			m.mu.Lock()
			delete(m.pending, c.ID)
			m.mu.Unlock()
			return Result{}, c, fmt.Errorf("challenge: notify failed: %w", err)
		}
	}

	remaining := time.Until(c.Deadline)
	if remaining <= 0 {
		remaining = time.Nanosecond
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case res := <-p.decided:
		m.mu.Lock()
		delete(m.pending, c.ID)
		m.mu.Unlock()
		return res, c, nil
	case <-timer.C:
		m.mu.Lock()
		_, still := m.pending[c.ID]
		delete(m.pending, c.ID)
		m.mu.Unlock()
		if still {
			return Result{Approved: false, TimedOut: true, Reason: "challenge-timeout (default deny)"}, c, nil
		}
		// resolved concurrently between timer and lock — race with the
		// decided channel; the resolve path has already delivered a result.
		select {
		case res := <-p.decided:
			return res, c, nil
		default:
			return Result{Approved: false, TimedOut: true, Reason: "challenge-timeout (default deny)"}, c, nil
		}
	}
}

// Resolve resolves a pending challenge. The approver MUST be on the tool's
// allowlist (authenticated AND authorized — §9). Single-use: the pending
// entry is consumed on first resolve. Returns error for unknown/expired/
// unauthorized resolutions (all logged by callers via receipts).
func (m *Manager) Resolve(id, approver string, approve bool) error {
	m.mu.Lock()
	p, ok := m.pending[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("challenge: unknown or already-resolved challenge %q", id)
	}
	if m.now().After(p.ch.Deadline) {
		delete(m.pending, id)
		m.mu.Unlock()
		return fmt.Errorf("challenge: %q expired", id)
	}
	if !p.allow[approver] {
		m.mu.Unlock()
		// logged and rejected — a click from a non-allowlisted user never approves
		return fmt.Errorf("challenge: approver %q not on allowlist for tool %q", approver, p.ch.Tool)
	}
	delete(m.pending, id) // single-use consume
	m.mu.Unlock()
	res := Result{Approved: approve, Approver: approver}
	if approve {
		res.Reason = "approved by " + approver
	} else {
		res.Reason = "denied by " + approver
	}
	p.decided <- res
	return nil
}

func (m *Manager) resolveInternal(id string, res Result) {
	m.mu.Lock()
	p, ok := m.pending[id]
	if ok {
		delete(m.pending, id)
	}
	m.mu.Unlock()
	if ok {
		p.decided <- res
	}
}

// Pending returns a snapshot of pending challenges (for the dashboard).
func (m *Manager) Pending() []Challenge {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Challenge, 0, len(m.pending))
	for _, p := range m.pending {
		out = append(out, p.ch)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Redact builds the redacted payload (§5.4). Secret-bearing segments are
// masked; untrusted block text appears only as short clearly-marked hostile
// excerpts; blocks are referenced by HMAC. The caught exfil attempt never
// delivers the secret to Slack.
func Redact(tool string, args map[string]any, matched []labels.Block, classifier *labels.Classifier, receiptKey []byte) *Redacted {
	r := &Redacted{Tool: tool}
	names := make([]string, 0, len(args))
	for k := range args {
		names = append(names, k)
	}
	sort.Strings(names)
	// values that carry a matched high-sensitivity block are masked by label,
	// not shape: a labeled secret need not look like a credential
	var high []labels.Block
	for _, b := range matched {
		if b.High() {
			high = append(high, b)
		}
	}
	m := labels.NewMatcher()
	for _, k := range names {
		// Keys are agent-controlled exactly like values: a secret planted in
		// a KEY must not reach Slack either (round-9 finding). Same masking
		// treatment applies to names.
		name := k
		if len(high) > 0 && len(m.Matches(k, high)) > 0 {
			name = fullMask(k)
		} else {
			name = maskValue(k, classifier)
		}
		v := fmt.Sprintf("%v", args[k])
		shape := ""
		if len(high) > 0 && len(m.Matches(v, high)) > 0 {
			shape = fullMask(v)
		} else {
			shape = maskValue(v, classifier)
		}
		r.Args = append(r.Args, RedactedArg{Name: name, Shape: shape})
	}
	seen := map[string]bool{}
	for _, b := range matched {
		if seen[b.ID] {
			continue
		}
		seen[b.ID] = true
		r.Blocks = append(r.Blocks, BlockRef{ID: b.ID, Source: b.Source, HMAC: blockRef(b.Text, receiptKey)})
		// Only NON-SENSITIVE untrusted blocks are excerpted (attacker text,
		// clearly marked). High-sensitivity blocks — a secrets-file read is
		// untrusted-by-path AND high — are HMAC-referenced only: the caught
		// exfil attempt never delivers the secret to Slack (§5.4).
		if b.Untrusted() && !b.High() {
			// A normal label can be wrong: if the excerpt itself looks like a
			// secret it is withheld and HMAC-referenced instead — redacted by
			// construction, never delivered to Slack or the dashboard (§5.4).
			x := excerpt(b.Text, 160)
			if classifier.LooksHigh(x) || looksSensitiveKey(x) {
				x = "(high-looking content withheld; ref " + blockRef(b.Text, receiptKey) + ")"
			}
			r.HostileExcerpts = append(r.HostileExcerpts, x)
		}
	}
	return r
}

// maskValue masks secret-looking segments: the first 3 chars survive so the
// approver can tell which credential shape this is; everything else of a
// high-sensitivity-looking value becomes ▒.
func maskValue(v string, classifier *labels.Classifier) string {
	shape := fmt.Sprintf("len=%d", len(v))
	if v == "" {
		return "(empty)"
	}
	if !classifier.LooksHigh(v) && !looksSensitiveKey(v) {
		// Not secret-shaped — but an unrecognized secret is exactly one the
		// classifier misses, so no raw argument text is ever emitted: the
		// approver gets shape only (redacted by construction).
		return fmt.Sprintf("(len=%d, charset=%s)", len(v), charsetClass(v))
	}
	prefix := v
	if len(prefix) > 3 {
		prefix = prefix[:3]
	}
	masked := strings.Repeat("▒", minInt(len(v)-len(prefix), 12))
	return prefix + masked + " (" + shape + ")"
}

// fullMask hides a value entirely (no prefix): it carries content from a
// high-sensitivity block.
func fullMask(v string) string {
	return strings.Repeat("▒", minInt(len(v), 12)) + fmt.Sprintf(" (len=%d, carries high-sensitivity block content)", len(v))
}

func looksSensitiveKey(s string) bool {
	low := strings.ToLower(s)
	for _, k := range []string{"password", "passwd", "secret", "token", "api_key", "apikey", "private_key", "bearer"} {
		if strings.Contains(low, k) {
			return true
		}
	}
	return false
}

func blockRef(text string, key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(text))
	return hex.EncodeToString(m.Sum(nil))[:12]
}

func excerpt(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// charsetClass summarizes which character classes a value mixes, without
// revealing any of its content.
func charsetClass(v string) string {
	var lower, upper, digit, sym bool
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			sym = true
		}
	}
	out := ""
	if lower {
		out += "lower"
	}
	if upper {
		out += "+upper"
	}
	if digit {
		out += "+digit"
	}
	if sym {
		out += "+sym"
	}
	if out == "" {
		return "empty"
	}
	return out
}

// ReceiptForChallenge builds the post-resolution receipt fields.
func (r Result) ReceiptFields(c Challenge) (decision, approver, rule string) {
	decision = "deny"
	if r.Approved {
		decision = "approve"
	}
	approver = r.Approver
	if r.TimedOut {
		decision = "deny"
		approver = ""
		rule = c.Rule + "+challenge-timeout"
		return
	}
	rule = c.Rule + "+challenge-resolved"
	return
}

// Verified is a helper used by the dashboard to show the challenge outcome
// against the receipt log.
func Verified(logPath, challengeID string) ([]receipts.Entry, error) {
	return receipts.Search(logPath, "", "", "", challengeID)
}
