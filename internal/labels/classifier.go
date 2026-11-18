package labels

import (
	"math"
	"regexp"
	"strings"
)

// Classifier is the rule-based argument classifier (PRD §5.3 step 3): when
// containment did not propagate a sensitivity label, argument class decides
// whether the content should be treated as high sensitivity. Defaults bias
// high — a false "high" costs one challenge, a false "normal" can cost a
// secret (PRD §11, named bypass: sensitivity-classifier miss).
type Classifier struct {
	Patterns []*regexp.Regexp
}

// DefaultClassifier ships the built-in secret shapes. Extensible via policy
// in later revisions; correctness of the shipped set is pinned by tests.
func DefaultClassifier() *Classifier {
	pats := []string{
		`AKIA[0-9A-Z]{16}`,                   // AWS access key id
		`(?i)sk-[a-z0-9_-]{20,}`,             // OpenAI-style key
		`ghp_[A-Za-z0-9]{30,}`,               // GitHub PAT
		`github_pat_[A-Za-z0-9_]{20,}`,       // GitHub fine-grained PAT
		`xox[bpars]-[A-Za-z0-9-]{10,}`,       // Slack token
		`-----BEGIN [A-Z ]*PRIVATE KEY-----`, // PEM private key
		`(?i)bearer\s+[a-z0-9._~+/=-]{20,}`,  // bearer credential
		`(?i)\b(password|passwd|secret|token|api[_-]?key|private[_-]?key)\b\s*[=:]\s*["']?[^\s"']{8,}`,
		`(?i)\b(AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|SLACK_BOT_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY)\b`,
	}
	out := make([]*regexp.Regexp, 0, len(pats))
	for _, p := range pats {
		out = append(out, regexp.MustCompile(p))
	}
	return &Classifier{Patterns: out}
}

// LooksHigh applies the shipped patterns plus an entropy heuristic: any long
// high-entropy run looks like a credential and is treated as high.
func (c *Classifier) LooksHigh(s string) bool {
	for _, p := range c.Patterns {
		if p.MatchString(s) {
			return true
		}
	}
	return highEntropyRun(s)
}

// highEntropyRun finds a credential-alphabet run of >= 24 chars that mixes
// letters and digits (>= 2 digits) and whose Shannon entropy exceeds 3.5
// bits per char — random-looking material. The letter+digit requirement
// keeps ordinary prose, hostnames and paths ("//registry.internal/preview")
// from reading as credentials; '.' and '~' end a run for the same reason.
func highEntropyRun(s string) bool {
	run := make([]rune, 0, 64)
	scan := func() bool {
		if len(run) < 24 {
			return false
		}
		freq := map[rune]int{}
		letters, digits := 0, 0
		for _, r := range run {
			freq[r]++
			switch {
			case r >= '0' && r <= '9':
				digits++
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
				letters++
			}
		}
		if letters == 0 || digits < 2 {
			return false
		}
		h := 0.0
		for _, n := range freq {
			p := float64(n) / float64(len(run))
			h += -p * math.Log2(p)
		}
		return h > 3.5 // h is already bits per char
	}
	for _, r := range s {
		if isCredRune(r) {
			run = append(run, r)
			continue
		}
		if scan() {
			return true
		}
		run = run[:0]
	}
	return scan()
}

func isCredRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune("+/=_-", r)
}
