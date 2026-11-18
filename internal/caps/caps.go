// Package caps implements task-scoped capability tokens (PRD §5.2):
// sensitivity-bearing caps, minted at task start from the operator's policy
// only, with two hard death conditions — immediate revocation on task end
// (no grace window) and an absolute wall-clock TTL, whichever comes first.
package caps

import (
	"fmt"
	"sync"
	"time"

	"github.com/adventurewave-labs/referee/internal/labels"
)

// Cap is one capability. ScopeArg names the argument the pattern applies to;
// an empty ScopeArg means the cap covers the tool as a whole. A cap covers a
// call up to its declared sensitivity: a SensHigh call requires a SensHigh
// cap on the matching tool/scope (a normal cap never authorizes a high call).
type Cap struct {
	Tool        string
	ScopeArg    string
	Pattern     string
	Sensitivity labels.Sensitivity
}

// Key identifies the cap the way manifests reference it.
func (c Cap) Key() string { return c.Tool + "|" + c.Pattern }

// Covers reports whether this cap authorizes a call to tool with the given
// scope argument value and required sensitivity.
func (c Cap) Covers(tool, scopeVal string, sens labels.Sensitivity) bool {
	if c.Tool != tool {
		return false
	}
	if !c.Sensitivity.Covers(sens) {
		return false
	}
	if c.ScopeArg == "" {
		return true // tool-level cap
	}
	return labels.GlobMatch(c.Pattern, scopeVal)
}

// Token is a task-scoped capability set.
type Token struct {
	TaskID    string
	TaskClass string
	Caps      []Cap
	IssuedAt  time.Time
	ExpiresAt time.Time // absolute, wall-clock, mandatory
	Ended     bool
	Clamped   bool // true when the requested TTL was clamped to the ceiling
}

// Alive reports whether the token is still usable: not ended and inside its
// absolute TTL. There is no grace window on either condition.
func (t *Token) Alive(now time.Time) bool {
	return !t.Ended && now.Before(t.ExpiresAt)
}

// Covers finds a cap covering (tool, scopeVal, sens). scopeVal is matched
// against every cap's pattern regardless of its ScopeArg — use CoversCall
// when the call's arguments are known.
func (t *Token) Covers(tool, scopeVal string, sens labels.Sensitivity) bool {
	for _, c := range t.Caps {
		if c.Covers(tool, scopeVal, sens) {
			return true
		}
	}
	return false
}

// CoversCall finds a cap covering the call, matching each cap's pattern
// against the value of that cap's OWN scope argument (argValue looks it up),
// so a cap scoped to one argument can never authorize via another's value.
func (t *Token) CoversCall(tool string, argValue func(arg string) string, sens labels.Sensitivity) bool {
	for _, c := range t.Caps {
		if c.Covers(tool, argValue(c.ScopeArg), sens) {
			return true
		}
	}
	return false
}

// Store holds live tokens per task.
type Store struct {
	mu     sync.Mutex
	tokens map[string]*Token
	now    func() time.Time
}

func NewStore(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{tokens: map[string]*Token{}, now: now}
}

// Mint creates a task token. The caller must have narrowed the cap list via
// policy.NarrowCaps — Mint never widens anything it is given. A TTL above
// the operator ceiling is clamped down (never up), recorded in Clamped.
func (s *Store) Mint(taskID, class string, ttl, ceiling time.Duration, cl ...Cap) (*Token, error) {
	if taskID == "" {
		return nil, fmt.Errorf("caps: mint requires a task id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tokens[taskID]; exists {
		return nil, fmt.Errorf("caps: task %q already has a token", taskID)
	}
	clamped := false
	if ceiling > 0 && ttl > ceiling {
		ttl = ceiling
		clamped = true
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("caps: mint requires a positive ttl")
	}
	t := &Token{
		TaskID:    taskID,
		TaskClass: class,
		Caps:      cl,
		IssuedAt:  s.now(),
		ExpiresAt: s.now().Add(ttl),
		Clamped:   clamped,
	}
	s.tokens[taskID] = t
	return t, nil
}

// End revokes the task token immediately (task-end signal). Returns whether
// a live token was killed.
func (s *Store) End(taskID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[taskID]
	if !ok || t.Ended {
		return false
	}
	t.Ended = true
	return true
}

// Get returns the token for a task, or nil. Expired tokens are pruned so the
// TTL kills tokens even when no task-end signal ever arrives.
func (s *Store) Get(taskID string) *Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[taskID]
	if !ok {
		return nil
	}
	if !t.Alive(s.now()) {
		delete(s.tokens, taskID)
		return nil
	}
	return t
}
