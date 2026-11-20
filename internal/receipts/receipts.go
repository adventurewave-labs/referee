// Package receipts implements the verifiable decision log (PRD §5.4): an
// append-only, hash-chained JSONL log. Every entry carries a keyed HMAC of
// the canonical arguments (low-entropy arguments cannot be dictionary-
// reversed from an exported log); batch heads are signed with a local ed25519
// keypair. Receipts never contain recoverable secrets — raw arguments are not
// retained in v1 (optional encrypted escrow is a later addition).
package receipts

import (
	"bufio"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Entry is one gate decision in the log.
type Entry struct {
	Seq      uint64    `json:"seq"`
	TS       time.Time `json:"ts"`
	Task     string    `json:"task"`
	Tool     string    `json:"tool"`
	Rule     string    `json:"rule"`
	Decision string    `json:"decision"` // approve|challenge|deny
	Approver string    `json:"approver,omitempty"`
	BlockIDs []string  `json:"block_ids,omitempty"`
	Axis     string    `json:"axis"` // e.g. "integrity=tainted conf=high"
	ArgsHMAC string    `json:"args_hmac"`
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
}

// Head is a signed batch head.
type Head struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
	Sig  string `json:"sig"` // ed25519 over "referee-head|<seq>|<hash>"
}

// SigBytes decodes the hex signature.
func (h Head) SigBytes() []byte {
	b, _ := hex.DecodeString(h.Sig)
	return b
}

// Record is what the caller supplies. ArgsCanonical is used ONLY to compute
// the HMAC — the log stores the HMAC, never the arguments.
type Record struct {
	Task, Tool, Rule, Decision, Approver string
	BlockIDs                             []string
	Axis                                 string
	ArgsCanonical                        string
}

// Log is the append-only receipt chain.
type Log struct {
	mu        sync.Mutex
	path      string
	headsPath string
	hmacKey   []byte
	priv      ed25519.PrivateKey
	batchSize int
	seq       uint64
	prevHash  string
}

const genesisHash = "genesis"

// Open opens (creating if absent) a receipt log, resuming and verifying the
// chain — a tampered log refuses to open (fail closed).
func Open(path, headsPath string, hmacKey []byte, priv ed25519.PrivateKey, batchSize int) (*Log, error) {
	if len(hmacKey) == 0 {
		return nil, fmt.Errorf("receipts: empty args-hmac key")
	}
	if batchSize <= 0 {
		batchSize = 100
	}
	l := &Log{
		path: path, headsPath: headsPath, hmacKey: hmacKey,
		priv: priv, batchSize: batchSize, prevHash: genesisHash,
	}
	entries, err := ReadAll(path)
	if err != nil {
		return nil, err
	}
	if err := checkChain(entries); err != nil {
		return nil, err
	}
	// signed heads bind the chain to the key: a log rewritten with
	// recomputed hashes conflicts with them and refuses to open. Entries
	// past the last signed head must be fewer than one batch, otherwise
	// heads were removed (assumes batch size was not shrunk across runs).
	if headsPath != "" && priv != nil {
		pub, _ := priv.Public().(ed25519.PublicKey)
		_, last, err := verifyHeads(entries, headsPath, pub, false)
		if err != nil {
			return nil, err
		}
		if uint64(len(entries))-last >= uint64(batchSize) {
			return nil, fmt.Errorf("receipts: %d entries after the last signed head (batch %d) — heads missing or truncated", uint64(len(entries))-last, batchSize)
		}
		// create the heads file up front so a later deletion is detectable;
		// the meta line records the batch size so Verify can tell a fresh
		// log (no batch has flushed yet) from a truncated heads file
		hf, err := os.OpenFile(headsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, err
		}
		if st, serr := hf.Stat(); serr == nil && st.Size() == 0 {
			sig := ed25519.Sign(priv, headsMetaMessage(batchSize))
			meta, _ := json.Marshal(map[string]any{
				"heads_meta": map[string]int{"batch": batchSize},
				"sig":        hex.EncodeToString(sig),
			})
			hf.Write(append(meta, '\n'))
		}
		hf.Close()
	}
	if len(entries) > 0 {
		l.seq = entries[len(entries)-1].Seq
		l.prevHash = entries[len(entries)-1].Hash
	}
	return l, nil
}

// Append adds one decision and, at batch boundaries, signs the running head.
func (l *Log) Append(r Record) (Entry, Head, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Entry{
		Seq:      l.seq + 1,
		TS:       time.Now().UTC(),
		Task:     r.Task,
		Tool:     r.Tool,
		Rule:     r.Rule,
		Decision: r.Decision,
		Approver: r.Approver,
		BlockIDs: r.BlockIDs,
		Axis:     r.Axis,
		ArgsHMAC: ArgsHMAC(l.hmacKey, r.ArgsCanonical),
		PrevHash: l.prevHash,
	}
	e.Hash = e.computeHash()
	line, err := json.Marshal(e)
	if err != nil {
		return e, Head{}, err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return e, Head{}, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return e, Head{}, err
	}
	l.seq = e.Seq
	l.prevHash = e.Hash

	var head Head
	if l.seq%uint64(l.batchSize) == 0 && l.priv != nil {
		head = l.signHeadLocked()
		if l.headsPath != "" {
			if err := appendHead(l.headsPath, head); err != nil {
				return e, head, err
			}
		}
	}
	return e, head, nil
}

func appendHead(path string, h Head) error {
	hl, err := json.Marshal(h)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(hl, '\n'))
	return err
}

func (l *Log) signHeadLocked() Head {
	return signHead(l.priv, l.seq, l.prevHash)
}

func signHead(priv ed25519.PrivateKey, seq uint64, hash string) Head {
	sig := ed25519.Sign(priv, headMessage(seq, hash))
	return Head{Seq: seq, Hash: hash, Sig: hex.EncodeToString(sig)}
}

func headMessage(seq uint64, hash string) []byte {
	return []byte(fmt.Sprintf("referee-head|%d|%s", seq, hash))
}

// headsMetaMessage is the signed payload of the heads-file meta line.
func headsMetaMessage(batch int) []byte {
	return []byte(fmt.Sprintf("referee-heads-meta|batch=%d", batch))
}

// computeHash chains the entry onto its predecessor over an UNAMBIGUOUS
// encoding: every field is length-prefixed, so delimiter characters inside
// field values (e.g. Task="a|b" vs Tool="b|c" shifts) can no longer produce
// identical hash inputs for different entries (round-13, P1).
// hashFormatVersion bumps whenever the hash input encoding changes; logs
// written by an older format fail verification with an explicit message
// instead of a confusing hash mismatch (round-13 follow-up).
const hashFormatVersion = "referee-receipts-hashfmt=2"

func (e Entry) computeHash() string {
	h := sha256.New()
	writeField := func(v string) {
		fmt.Fprintf(h, "%x:", len(v))
		h.Write([]byte(v))
		h.Write([]byte("\x00"))
	}
	writeField(hashFormatVersion)
	fmt.Fprintf(h, "%x:", e.Seq)
	writeField(e.TS.UTC().Format(time.RFC3339Nano))
	writeField(e.Task)
	writeField(e.Tool)
	writeField(e.Rule)
	writeField(e.Decision)
	writeField(e.Approver)
	writeField(strings.Join(e.BlockIDs, ","))
	writeField(e.Axis)
	writeField(e.ArgsHMAC)
	writeField(e.PrevHash)
	return hex.EncodeToString(h.Sum(nil))
}

// ArgsHMAC is the keyed HMAC over canonical arguments.
func ArgsHMAC(key []byte, canonicalArgs string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(canonicalArgs))
	return hex.EncodeToString(m.Sum(nil))
}

// ReadAll loads every entry from a log file.
func ReadAll(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return out, fmt.Errorf("receipts: %s: bad entry: %w", path, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// checkChain validates seq continuity and hash links.
func checkChain(entries []Entry) error {
	prev := genesisHash
	for i, e := range entries {
		if e.Seq != uint64(i+1) {
			return fmt.Errorf("receipts: seq discontinuity at %d (want %d)", e.Seq, i+1)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("receipts: broken chain at seq %d", e.Seq)
		}
		if e.Hash != e.computeHash() {
			return fmt.Errorf("receipts: hash mismatch at seq %d — log tampered, or written by an older hash format (v1 logs are not readable by this version; archive or migrate)", e.Seq)
		}
		prev = e.Hash
	}
	return nil
}

// Verify walks the chain checking seq continuity, hashes, and — when a
// public key is given — every batch-head signature. Returns the number of
// entries and heads verified.
func Verify(path, headsPath string, pub ed25519.PublicKey) (int, int, error) {
	entries, err := ReadAll(path)
	if err != nil {
		return 0, 0, err
	}
	if err := checkChain(entries); err != nil {
		return 0, 0, err
	}
	heads := 0
	if headsPath != "" && pub != nil {
		n, _, err := verifyHeads(entries, headsPath, pub, true)
		if err != nil {
			return len(entries), n, err
		}
		heads = n
	}
	return len(entries), heads, nil
}

// verifyHeads checks every signed batch head in headsPath against the chain:
// valid signature, seq inside the log, hash equal to the entry it signs.
// Returns the number of heads verified and the highest signed seq. A missing
// heads file is an error when the log has entries and mustExist is set —
// deleting the signature evidence must not read as success.
func verifyHeads(entries []Entry, headsPath string, pub ed25519.PublicKey, mustExist bool) (int, uint64, error) {
	hf, err := os.Open(headsPath)
	if os.IsNotExist(err) {
		if mustExist && len(entries) > 0 {
			return 0, 0, fmt.Errorf("receipts: heads file %s missing — signed-head evidence absent", headsPath)
		}
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	defer hf.Close()
	heads := 0
	var last uint64
	metaBatch := 0
	lineNo := 0
	sc := bufio.NewScanner(hf)
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if lineNo == 1 {
			var meta struct {
				HeadsMeta struct {
					Batch int `json:"batch"`
				} `json:"heads_meta"`
				Sig string `json:"sig"`
			}
			if jerr := json.Unmarshal([]byte(line), &meta); jerr == nil && meta.HeadsMeta.Batch > 0 {
				// the meta line is signed evidence: a forged or unsigned batch
				// size is treated as absent — the empty-heads refusal below
				// then fires fail-closed (round-7 finding)
				sig, serr2 := hex.DecodeString(meta.Sig)
				if serr2 != nil || meta.HeadsMeta.Batch <= 0 ||
					!ed25519.Verify(pub, headsMetaMessage(meta.HeadsMeta.Batch), sig) {
					return 0, 0, fmt.Errorf("receipts: heads file %s has an invalid heads_meta signature", headsPath)
				}
				metaBatch = meta.HeadsMeta.Batch
				continue
			}
		}
		var h Head
		if err := json.Unmarshal([]byte(line), &h); err != nil {
			return heads, last, fmt.Errorf("receipts: bad head: %w", err)
		}
		if int(h.Seq) > len(entries) || h.Seq == 0 {
			return heads, last, fmt.Errorf("receipts: head seq %d beyond log", h.Seq)
		}
		if !ed25519.Verify(pub, headMessage(h.Seq, h.Hash), h.SigBytes()) {
			return heads, last, fmt.Errorf("receipts: bad head signature at seq %d", h.Seq)
		}
		if entries[h.Seq-1].Hash != h.Hash {
			return heads, last, fmt.Errorf("receipts: head hash mismatch at seq %d", h.Seq)
		}
		if h.Seq > last {
			last = h.Seq
		}
		heads++
	}
	if err := sc.Err(); err != nil {
		return heads, last, err
	}
	if mustExist && len(entries) > 0 {
		// the signed meta line is load-bearing evidence: its absence means the
		// heads file was rewritten or truncated below line one
		if metaBatch == 0 {
			return 0, 0, fmt.Errorf("receipts: heads file %s has no valid heads_meta line — signature evidence absent", headsPath)
		}
		// a fresh log shorter than one batch has legitimately never flushed a
		// head; beyond that, zero heads means the evidence was removed
		if heads == 0 {
			if uint64(len(entries)) < uint64(metaBatch) {
				return 0, 0, nil
			}
			return 0, 0, fmt.Errorf("receipts: heads file %s contains no signed heads — signature evidence absent", headsPath)
		}
		// unsigned tail: entries after the last signed head must be fewer
		// than one batch, else head evidence was removed (same rule Open
		// enforces on reopen — round-7 finding)
		if uint64(len(entries))-last >= uint64(metaBatch) {
			return heads, last, fmt.Errorf("receipts: %d entries after the last signed head (batch %d) — heads missing or truncated", uint64(len(entries))-last, metaBatch)
		}
	}
	return heads, last, nil
}

// Search filters entries by non-empty predicate fields.
func Search(path, task, tool, decision, rule string) ([]Entry, error) {
	entries, err := ReadAll(path)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range entries {
		if task != "" && e.Task != task {
			continue
		}
		if tool != "" && e.Tool != tool {
			continue
		}
		if decision != "" && e.Decision != decision {
			continue
		}
		if rule != "" && !strings.Contains(e.Rule, rule) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyEntries validates a parsed entry slice in memory: seq continuity and
// hash links. Used by callers that read the log once and want analysis to
// run on the SAME verified snapshot (no TOCTOU re-read).
func VerifyEntries(entries []Entry) error { return checkChain(entries) }
