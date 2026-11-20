package receipts

import (
	"time"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempLog(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "receipts.jsonl"), filepath.Join(dir, "heads.jsonl")
}

func newSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestChainAppendVerify(t *testing.T) {
	logPath, headsPath := tempLog(t)
	priv := newSigningKey(t)
	l, err := Open(logPath, headsPath, []byte("test-hmac-key"), priv, 4)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 10; i++ {
		_, _, err := l.Append(Record{
			Task: "t1", Tool: "send_email", Rule: "auto:clean", Decision: "approve",
			Axis: "integrity=not-detected conf=normal", ArgsCanonical: `{"body":"hi"}`,
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	n, heads, err := Verify(logPath, headsPath, priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n != 10 {
		t.Errorf("want 10 entries, got %d", n)
	}
	if heads != 2 { // seq 4 and seq 8 signed with batch size 4
		t.Errorf("want 2 heads, got %d", heads)
	}
}

func TestTamperDetected(t *testing.T) {
	logPath, _ := tempLog(t)
	l, _ := Open(logPath, "", []byte("k"), nil, 100)
	for i := 0; i < 3; i++ {
		l.Append(Record{Task: "t", Tool: "x", Rule: "r", Decision: "approve", ArgsCanonical: "{}"})
	}
	// tamper: flip a decision in the first entry
	b, _ := os.ReadFile(logPath)
	tampered := strings.Replace(string(b), `"decision":"approve"`, `"decision":"deny"`, 1)
	os.WriteFile(logPath, []byte(tampered), 0o600)

	if _, _, err := Verify(logPath, "", nil); err == nil || !strings.Contains(err.Error(), "tampered") {
		t.Fatalf("tampered log must fail verification, got %v", err)
	}
	// and refuse to reopen
	if _, err := Open(logPath, "", []byte("k"), nil, 100); err == nil {
		t.Fatalf("reopening a tampered log must fail closed")
	}
}

func TestResumeChain(t *testing.T) {
	logPath, _ := tempLog(t)
	l, _ := Open(logPath, "", []byte("k"), nil, 100)
	l.Append(Record{Task: "t", Tool: "x", Rule: "r1", Decision: "approve", ArgsCanonical: "{}"})
	l.Append(Record{Task: "t", Tool: "x", Rule: "r2", Decision: "deny", ArgsCanonical: "{}"})

	// reopening resumes seq/prevHash
	l2, err := Open(logPath, "", []byte("k"), nil, 100)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	e, _, err := l2.Append(Record{Task: "t", Tool: "x", Rule: "r3", Decision: "challenge", ArgsCanonical: "{}"})
	if err != nil {
		t.Fatalf("append after reopen: %v", err)
	}
	if e.Seq != 3 {
		t.Errorf("chain must resume at seq 3, got %d", e.Seq)
	}
	if _, _, err := Verify(logPath, "", nil); err != nil {
		t.Fatalf("verify after resume: %v", err)
	}
}

// §5.4: args-hmac is a keyed HMAC — identical args under different keys give
// different HMACs (exported logs cannot be dictionary-reversed without the key).
func TestArgsHMACKeyed(t *testing.T) {
	h1 := ArgsHMAC([]byte("key-one"), `{"body":"hi"}`)
	h2 := ArgsHMAC([]byte("key-two"), `{"body":"hi"}`)
	if h1 == h2 {
		t.Fatalf("HMAC must depend on the deployment key")
	}
	if h1 != ArgsHMAC([]byte("key-one"), `{"body":"hi"}`) {
		t.Fatalf("HMAC must be deterministic under the same key")
	}
}

func TestSearch(t *testing.T) {
	logPath, _ := tempLog(t)
	l, _ := Open(logPath, "", []byte("k"), nil, 100)
	l.Append(Record{Task: "t1", Tool: "send_email", Rule: "auto:clean", Decision: "approve", ArgsCanonical: "{}"})
	l.Append(Record{Task: "t2", Tool: "bash", Rule: "cap:missing", Decision: "deny", ArgsCanonical: "{}"})

	got, err := Search(logPath, "t2", "", "deny", "")
	if err != nil || len(got) != 1 || got[0].Tool != "bash" {
		t.Fatalf("search failed: %v %+v", err, got)
	}
	got, _ = Search(logPath, "", "", "", "auto")
	if len(got) != 1 {
		t.Fatalf("rule substring search failed")
	}
}

// rewriting the log with recomputed hashes keeps the unkeyed chain valid but
// conflicts with the signed heads: reopen and verify must both refuse.
func TestRewriteWithRecomputedHashesRefused(t *testing.T) {
	logPath, headsPath := tempLog(t)
	priv := newSigningKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	l, err := Open(logPath, headsPath, []byte("k"), priv, 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 4; i++ {
		if _, _, err := l.Append(Record{Task: "t", Tool: "x", Rule: "r", Decision: "deny", ArgsCanonical: "{}"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	entries, err := ReadAll(logPath)
	if err != nil {
		t.Fatal(err)
	}
	prev := genesisHash
	var out []byte
	for i := range entries {
		if i == 0 {
			entries[i].Decision = "approve"
		}
		entries[i].PrevHash = prev
		entries[i].Hash = entries[i].computeHash()
		prev = entries[i].Hash
		b, _ := json.Marshal(entries[i])
		out = append(out, append(b, '\n')...)
	}
	os.WriteFile(logPath, out, 0o600)

	if _, err := Open(logPath, headsPath, []byte("k"), priv, 2); err == nil {
		t.Fatalf("reopen must refuse a log that conflicts with its signed heads")
	}
	if _, _, err := Verify(logPath, headsPath, pub); err == nil {
		t.Fatalf("verify must refuse a log that conflicts with its signed heads")
	}
}

// deleting the heads file must not verify as success, and a reopen must
// notice that more than a batch of entries has no signed head.
func TestMissingHeadsRefused(t *testing.T) {
	logPath, headsPath := tempLog(t)
	priv := newSigningKey(t)
	l, _ := Open(logPath, headsPath, []byte("k"), priv, 2)
	for i := 0; i < 4; i++ {
		l.Append(Record{Task: "t", Tool: "x", Rule: "r", Decision: "deny", ArgsCanonical: "{}"})
	}
	os.Remove(headsPath)
	if _, _, err := Verify(logPath, headsPath, priv.Public().(ed25519.PublicKey)); err == nil {
		t.Fatalf("verify with a deleted heads file must fail")
	}
	if _, err := Open(logPath, headsPath, []byte("k"), priv, 2); err == nil {
		t.Fatalf("reopen with heads missing for a full batch must fail")
	}
}

// truncating the heads file to zero bytes must fail verification exactly
// like deleting it — an empty heads file is absent signature evidence.
func TestTruncatedHeadsRefused(t *testing.T) {
	logPath, headsPath := tempLog(t)
	priv := newSigningKey(t)
	l, _ := Open(logPath, headsPath, []byte("k"), priv, 2)
	for i := 0; i < 4; i++ {
		l.Append(Record{Task: "t", Tool: "x", Rule: "r", Decision: "deny", ArgsCanonical: "{}"})
	}
	if err := os.WriteFile(headsPath, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(logPath, headsPath, priv.Public().(ed25519.PublicKey)); err == nil {
		t.Fatalf("verify with an empty (truncated) heads file must fail")
	}
}

// a fresh deployment (log shorter than one batch) has legitimately never
// flushed a head — Verify must accept it via the heads meta line, while a
// truncated heads file on a mature log is still refused.
func TestFreshDeploymentVerifies(t *testing.T) {
	logPath, headsPath := tempLog(t)
	priv := newSigningKey(t)
	l, err := Open(logPath, headsPath, []byte("k"), priv, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := l.Append(Record{Task: "t", Tool: "x", Rule: "r", Decision: "deny", ArgsCanonical: "{}"}); err != nil {
			t.Fatal(err)
		}
	}
	n, heads, err := Verify(logPath, headsPath, priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("fresh log below one batch must verify: %v", err)
	}
	if n != 3 || heads != 0 {
		t.Fatalf("expected 3 entries / 0 heads, got %d/%d", n, heads)
	}
}

// the heads_meta line is signed evidence: a forged batch size must not
// excuse a truncated heads file.
func TestForgedHeadsMetaRefused(t *testing.T) {
	logPath, headsPath := tempLog(t)
	priv := newSigningKey(t)
	l, err := Open(logPath, headsPath, []byte("k"), priv, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := l.Append(Record{Task: "t", Tool: "x", Rule: "r", Decision: "deny", ArgsCanonical: "{}"}); err != nil {
			t.Fatal(err)
		}
	}
	forged := `{"heads_meta":{"batch":100000},"sig":"deadbeef"}`
	if err := os.WriteFile(headsPath, []byte(forged+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(logPath, headsPath, priv.Public().(ed25519.PublicKey)); err == nil {
		t.Fatalf("forged heads_meta must be refused")
	}
}

// removing tail heads beyond one batch must fail Verify exactly like it
// fails Open's reopen check.
func TestUnsignedTailRefused(t *testing.T) {
	logPath, headsPath := tempLog(t)
	priv := newSigningKey(t)
	l, err := Open(logPath, headsPath, []byte("k"), priv, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if _, _, err := l.Append(Record{Task: "t", Tool: "x", Rule: "r", Decision: "deny", ArgsCanonical: "{}"}); err != nil {
			t.Fatal(err)
		}
	}
	// keep meta + head@2 only: entries 3,4 lose their signed evidence
	lines := strings.Split(string(mustRead(t, headsPath)), "\n")
	var kept []string
	for _, ln := range lines {
		if ln == "" || strings.Contains(ln, `"seq":4"`) || strings.Contains(ln, `"seq":4`) {
			continue
		}
		kept = append(kept, ln)
	}
	if err := os.WriteFile(headsPath, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(logPath, headsPath, priv.Public().(ed25519.PublicKey)); err == nil {
		t.Fatalf("unsigned tail beyond one batch must be refused")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// round-13 P1-5: the hash encoding is unambiguous — delimiter characters
// inside field values can no longer make two different entries share a hash
// (and therefore a signed head).
func TestDelimiterAmbiguityClosed(t *testing.T) {
	mk := func(task, tool string) Entry {
		e := Entry{Seq: 1, TS: time.Unix(1_700_000_000, 0).UTC(), Task: task, Tool: tool,
			Rule: "r", Decision: "deny", Axis: "i", ArgsHMAC: "h", PrevHash: "p"}
		e.Hash = e.computeHash()
		return e
	}
	// The old pipe-separated encoding made these two entries produce the
	// IDENTICAL hash input — a swap between them was invisible to the chain
	// and to signed heads. The length-prefixed encoding must separate them.
	e1 := mk("a|b", "c")
	e2 := mk("a", "b|c")
	if e1.Hash == e2.Hash {
		t.Fatalf("delimiter-shifted field boundaries share a hash — the encoding is ambiguous")
	}
	// identical content must still hash identically (no nondeterminism)
	if mk("a|b", "c").Hash != e1.Hash {
		t.Fatalf("hash must be deterministic for identical entries")
	}
}

// round-81: VerifyEntries validates a parsed slice in memory — the TOCTOU
// fix for verify-then-analyze flows.
func TestVerifyEntriesInMemory(t *testing.T) {
	good := []Entry{
		{Seq: 1, TS: time.Unix(1_700_000_000, 0).UTC(), Task: "t", Tool: "x", Rule: "r", Decision: "approve", Axis: "a", ArgsHMAC: "h", PrevHash: "genesis", Hash: "aaa"},
		{Seq: 2, TS: time.Unix(1_700_000_001, 0).UTC(), Task: "t", Tool: "x", Rule: "r", Decision: "deny", Axis: "a", ArgsHMAC: "h", PrevHash: "aaa", Hash: "bbb"},
	}
	prev := "genesis"
	for i := range good {
		good[i].PrevHash = prev
		good[i].Hash = good[i].computeHash() // same package: use the real encoding
		prev = good[i].Hash
	}
	if err := VerifyEntries(good); err != nil {
		t.Fatalf("consistent chain must verify: %v", err)
	}
	broken := append([]Entry(nil), good...)
	broken[1].Rule = "tampered"
	if err := VerifyEntries(broken); err == nil {
		t.Fatalf("in-place tamper must fail verification")
	}
}
