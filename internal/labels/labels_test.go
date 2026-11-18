package labels

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
	"time"
)

func block(id, text string, t Trust, s Sensitivity) Block {
	return Block{ID: id, Source: "test", Trust: t, Sensitivity: s, IngestedAt: time.Now(), Text: text}
}

// §8: secret read from a secrets-dir path (high sensitivity), pasted into a
// gated sink argument in four encodings — each must gate as
// confidentiality-high via label propagation (per-normalization coverage).
func TestSecretEncodingsGateHigh(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLEwJalrXUtnFEMI"
	m := NewMatcher()
	blocks := []Block{block("b-0001", "aws_deploy_key="+secret, TrustUntrusted, SensHigh)}

	cases := map[string]string{
		"raw":         "deploy with key " + secret,
		"base64":      base64.StdEncoding.EncodeToString([]byte(secret)),
		"base64-raw":  base64.RawStdEncoding.EncodeToString([]byte(secret)),
		"url-encoded": url.QueryEscape("deploy key=" + secret),
		"hex":         hex.EncodeToString([]byte(secret)),
		"json-escape": `\"deploy key=` + secret + `\"`,
		"unicode":     `\u0064eploy key=` + secret,
	}
	for name, arg := range cases {
		matches := m.Matches(arg, blocks)
		if len(matches) == 0 {
			t.Errorf("%s: secret encoding not matched — label propagation missed (§8 regression)", name)
			continue
		}
		if matches[0].BlockID != "b-0001" {
			t.Errorf("%s: matched wrong block %s", name, matches[0].BlockID)
		}
	}
}

// The two labels propagate independently (§5.1, never conflated):
// a trusted-but-high block taints confidentiality but NOT integrity;
// an untrusted-but-normal block taints integrity but NOT confidentiality.
func TestIndependentAxisPropagation(t *testing.T) {
	m := NewMatcher()

	cred := block("b-cred", "token: ghp_" + strings.Repeat("a", 36), TrustTrusted, SensHigh)
	page := block("b-web", "the release checklist says deploy at noon sharp", TrustUntrusted, SensNormal)

	got := m.Matches("send token: ghp_"+strings.Repeat("a", 36), []Block{cred})
	if len(got) != 1 {
		t.Fatalf("trusted-high block must match (exfil path), got %d", len(got))
	}
	b := lookupBlock(cred.ID, []Block{cred})
	if !b.High() || b.Untrusted() {
		t.Errorf("trusted-high block must be high/NOT untrusted — axes conflated")
	}

	got = m.Matches("deploy at noon sharp", []Block{page})
	if len(got) != 1 {
		t.Fatalf("untrusted block must match (injection path), got %d", len(got))
	}
	b = lookupBlock(page.ID, []Block{page})
	if !b.Untrusted() || b.High() {
		t.Errorf("untrusted-normal block must be untrusted/NOT high — axes conflated")
	}
}

func lookupBlock(id string, blocks []Block) Block {
	for _, b := range blocks {
		if b.ID == id {
			return b
		}
	}
	return Block{}
}

func TestDecodings(t *testing.T) {
	variants := Decodings(base64.StdEncoding.EncodeToString([]byte("supersecret")))
	found := false
	for _, v := range variants {
		if strings.Contains(v, "supersecret") {
			found = true
		}
	}
	if !found {
		t.Fatalf("base64 decoding variant missing; got %v", variants)
	}

	// double encoding: url(base64(x))
	inner := base64.StdEncoding.EncodeToString([]byte("hunter2password"))
	double := url.QueryEscape(inner)
	variants = Decodings(double)
	found = false
	for _, v := range variants {
		if strings.Contains(v, "hunter2password") {
			found = true
		}
	}
	if !found {
		t.Fatalf("double-encoded value not decoded through both rounds")
	}

	// adversarial junk must terminate and stay bounded
	junk := "%2525252525252525252525%%%%%" + strings.Repeat("%%", 100)
	if len(Decodings(junk)) > maxVariants {
		t.Fatalf("decode fan-out exceeded bound")
	}
}

func TestNormalizeForMatch(t *testing.T) {
	a := NormalizeForMatch("Deploy  Checklist\n\t for  PR-42")
	b := NormalizeForMatch("deploy checklist for pr-42")
	if a != b {
		t.Errorf("normalization unstable: %q vs %q", a, b)
	}
}

func TestClassifierLooksHigh(t *testing.T) {
	c := DefaultClassifier()
	high := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"sk-proj-" + strings.Repeat("x", 30),
		"ghp_" + strings.Repeat("Q", 36),
		"-----BEGIN RSA PRIVATE KEY-----",
		"Bearer " + strings.Repeat("e", 30),
		"password=hunter2hunter2",
		strings.Repeat("aB3dEf7hIj9Lm1nP", 3), // high-entropy run >= 24
	}
	for _, s := range high {
		if !c.LooksHigh(s) {
			t.Errorf("classifier missed secret-shaped input: %q", s)
		}
	}
	normal := []string{
		"deploy the preview for PR 42",
		"hello world this is a normal sentence about testing",
		"",
	}
	for _, s := range normal {
		if c.LooksHigh(s) {
			t.Errorf("classifier flagged normal text as high: %q", s)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"/tmp/pr-42/**", "/tmp/pr-42/anything/deep.txt", true},
		{"/tmp/pr-42/**", "/tmp/other/file", false},
		{"registry.internal/*", "registry.internal/foo", true},
		{"registry.internal/*", "registry.internal/foo/bar", false},
		{"*.go", "main.go", true},
		{"*.go", "cmd/main.go", false},
		{"**", "anything/at/all", true},
		{"a?c", "abc", true},
		{"a?c", "abbc", false},
		{"", "", true},
		{"", "x", false},
	}
	for _, c := range cases {
		if got := GlobMatch(c.pattern, c.s); got != c.want {
			t.Errorf("GlobMatch(%q, %q) = %t, want %t", c.pattern, c.s, got, c.want)
		}
	}
}

func TestRegistryPathPolicy(t *testing.T) {
	r := Default()
	r.PathRules = []PathRule{
		{Pattern: "/home/op/.secrets/**", Trust: TrustUntrusted, Sensitivity: SensHigh},
		{Pattern: "/home/op/work/**", Trust: TrustUntrusted, Sensitivity: SensNormal},
	}
	tu, sh := r.ForPath("/home/op/.secrets/aws_key")
	if tu != TrustUntrusted || sh != SensHigh {
		t.Errorf("secrets path must be untrusted/high, got %s/%s", tu, sh)
	}
	tu, sh = r.ForPath("/home/op/work/notes.txt")
	if tu != TrustUntrusted || sh != SensNormal {
		t.Errorf("work path must be untrusted/normal, got %s/%s", tu, sh)
	}
	tu, sh = r.ForPath("/tmp/anything")
	if tu != TrustUntrusted || sh != SensNormal {
		t.Errorf("default file path must be untrusted/normal, got %s/%s", tu, sh)
	}
}

// fuzz seed corpus: decoding must never panic and must stay bounded
func FuzzDecodings(f *testing.F) {
	f.Add("%41%42%43")
	f.Add("YWJj")
	f.Add("414243")
	f.Add(`\u0041\u0042`)
	f.Add(strings.Repeat("%25", 50))
	f.Fuzz(func(t *testing.T, s string) {
		vs := Decodings(s)
		if len(vs) > maxVariants {
			t.Errorf("unbounded decode fan-out: %d variants", len(vs))
		}
	})
}
