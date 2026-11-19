package caps

import (
	"testing"
	"time"

	"github.com/adventurewave-labs/referee/internal/labels"
)

var base = time.Unix(1_700_000_000, 0)

func testStore() *Store {
	return NewStore(func() time.Time { return base })
}

func TestMintAndAlive(t *testing.T) {
	s := testStore()
	tok, err := s.Mint("t1", "deploy", 4*time.Hour, 4*time.Hour,
		Cap{Tool: "bash", Pattern: "make*"}, Cap{Tool: "net.post", Pattern: "*", Sensitivity: labels.SensHigh})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !tok.Alive(base.Add(time.Hour)) {
		t.Errorf("token must be alive inside its TTL")
	}
	if tok.Alive(base.Add(5 * time.Hour)) {
		t.Errorf("token must be dead past its absolute TTL — no grace window")
	}
	if _, err := s.Mint("t1", "deploy", time.Hour, 0); err == nil {
		t.Errorf("duplicate task id must refuse re-mint")
	}
}

func TestClampToCeiling(t *testing.T) {
	s := testStore()
	tok, err := s.Mint("t1", "deploy", 100*time.Hour, 4*time.Hour, Cap{Tool: "bash", Pattern: "*"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !tok.Clamped {
		t.Errorf("ttl above ceiling must be recorded as clamped")
	}
	// expiry is half-open: alive strictly before ExpiresAt, dead at it (fail closed)
	if !tok.Alive(base.Add(4*time.Hour-time.Second)) || tok.Alive(base.Add(4*time.Hour)) {
		t.Errorf("clamped ttl must be the ceiling exactly")
	}
}

func TestEndRevokesImmediately(t *testing.T) {
	s := testStore()
	if _, err := s.Mint("t1", "deploy", 4*time.Hour, 0, Cap{Tool: "bash", Pattern: "*"}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !s.End("t1") {
		t.Errorf("end of a live token must report true")
	}
	if s.End("t1") {
		t.Errorf("second end must report false (idempotent)")
	}
	if tok := s.Get("t1"); tok != nil {
		t.Errorf("ended token must not be returned — revocation is immediate")
	}
}

func TestSensitivityCoverage(t *testing.T) {
	normalCap := Cap{Tool: "net.post", Pattern: "*", Sensitivity: labels.SensNormal}
	highCap := Cap{Tool: "net.post", Pattern: "*", Sensitivity: labels.SensHigh}
	tok := &Token{Caps: []Cap{normalCap}}

	if !normalCap.Covers("net.post", "", labels.SensNormal) {
		t.Errorf("normal cap covers normal calls")
	}
	if normalCap.Covers("net.post", "", labels.SensHigh) {
		t.Errorf("NORMAL CAP MUST NEVER AUTHORIZE A HIGH CALL (§5.2)")
	}
	if !highCap.Covers("net.post", "", labels.SensHigh) {
		t.Errorf("high cap covers high calls")
	}
	if !highCap.Covers("net.post", "", labels.SensNormal) {
		t.Errorf("high cap covers normal calls (covers up to declared sensitivity)")
	}
	_ = tok
}

func TestScopePatterns(t *testing.T) {
	c := Cap{Tool: "write_file", ScopeArg: "path", Pattern: "/tmp/pr-42/**", Sensitivity: labels.SensNormal}
	if !c.Covers("write_file", "/tmp/pr-42/out.txt", labels.SensNormal) {
		t.Errorf("in-scope path must be covered")
	}
	if c.Covers("write_file", "/etc/passwd", labels.SensNormal) {
		t.Errorf("out-of-scope path must not be covered")
	}
	if c.Covers("read_file", "/tmp/pr-42/out.txt", labels.SensNormal) {
		t.Errorf("cap is tool-specific")
	}
	toolLevel := Cap{Tool: "bash", Pattern: "*"}
	if !toolLevel.Covers("bash", "", labels.SensNormal) {
		t.Errorf("tool-level cap (no scope arg) covers the whole tool")
	}
}

func TestTTLDiesWithoutTaskEnd(t *testing.T) {
	// §5.2: if a harness never sends task-end, the TTL alone kills the token.
	now := base
	s := NewStore(func() time.Time { return now })
	if _, err := s.Mint("t1", "deploy", time.Hour, 0, Cap{Tool: "bash", Pattern: "*"}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	now = base.Add(2 * time.Hour) // clock advances; no task_end ever sent
	if tok := s.Get("t1"); tok != nil {
		t.Errorf("expired token must be pruned/ignored: %+v", tok)
	}
}

// round-13 P1-1: path scopes authorize the CANONICALIZED value only —
// traversal outside the authorized directory must fail the pattern.
func TestScopeTraversalDenied(t *testing.T) {
	c := Cap{Tool: "write_file", ScopeArg: "path", Pattern: "/tmp/pr-42/**", Sensitivity: labels.SensNormal}
	if c.Covers("write_file", "/tmp/pr-42/../../etc/passwd", labels.SensNormal) {
		t.Fatalf("TRAVERSAL OUTSIDE THE SCOPE MATCHED THE PATTERN")
	}
	if c.Covers("write_file", "/tmp/pr-42/../other/file", labels.SensNormal) {
		t.Fatalf("sibling traversal must be denied")
	}
	// traversal that canonicalizes back INSIDE the scope is fine
	if !c.Covers("write_file", "/tmp/pr-42/./sub/../out.txt", labels.SensNormal) {
		t.Errorf("in-scope traversal that canonicalizes inside must be allowed")
	}
	// windows-style separators canonicalize too
	if c.Covers("write_file", "/tmp/pr-42\\..\\..\\etc\\passwd", labels.SensNormal) {
		t.Fatalf("backslash traversal must be denied")
	}
}
