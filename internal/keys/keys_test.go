package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// serve exports the pubkey as hex + trailing newline; LoadPubKey must load
// exactly that file format (round-3 finding #1 regression).
func TestLoadPubKeyRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "referee-pubkey.hex")
	if err := os.WriteFile(p, []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPubKey(p)
	if err != nil {
		t.Fatalf("load exported pubkey: %v", err)
	}
	if string(got) != string(pub) {
		t.Fatalf("pubkey round-trip mismatch")
	}
}
