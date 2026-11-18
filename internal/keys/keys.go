// Package keys handles Referee's per-deployment keys (PRD §5.4/§9): the
// args-HMAC key and the ed25519 receipt-signing keypair. Keys live on disk
// (0600) or in env — never in git, never in argv.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

// LoadOrCreateHMAC returns the args-HMAC key: from hex env value when set,
// else from path (created with 32 random bytes on first run).
func LoadOrCreateHMAC(envVal, path string) ([]byte, error) {
	if envVal != "" {
		if b, err := hex.DecodeString(envVal); err == nil && len(b) >= 16 {
			return b, nil
		}
		// raw (non-hex) env values are hashed to a stable 32-byte key
		h := sha256.Sum256([]byte(envVal))
		return h[:], nil
	}
	if st, err := os.Stat(path); err == nil {
		if st.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("keys: %s too permissive (%v): chmod 600", path, st.Mode().Perm())
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if hexDecoded, derr := hex.DecodeString(string(b)); derr == nil && len(hexDecoded) >= 16 {
			return hexDecoded, nil
		}
		return b, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(b)), 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

// LoadOrCreateSigning loads the ed25519 seed from path, creating a fresh
// keypair on first run. Returns the private key and the public key.
func LoadOrCreateSigning(path string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if st, err := os.Stat(path); err == nil {
		if st.Mode().Perm()&0o077 != 0 {
			return nil, nil, fmt.Errorf("keys: %s too permissive (%v): chmod 600", path, st.Mode().Perm())
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		seed, derr := hex.DecodeString(string(b))
		if derr != nil || len(seed) != ed25519.SeedSize {
			return nil, nil, fmt.Errorf("keys: %s is not a %d-byte hex ed25519 seed", path, ed25519.SeedSize)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		return priv, priv.Public().(ed25519.PublicKey), nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		return nil, nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}

// LoadPubKey loads a hex-encoded ed25519 public key for verification.
func LoadPubKey(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, derr := hex.DecodeString(string(b))
	if derr != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("keys: %s is not a %d-byte hex ed25519 public key", path, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
