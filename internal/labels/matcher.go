package labels

import (
	"strings"
	"unicode"
)

// Match records one block whose content influenced an argument.
type Match struct {
	BlockID string
	Exact   bool // exact (post-normalization) containment vs fuzzy token hit
}

// Matcher is the containment matcher (PRD §5.1): exact/fuzzy matching of
// context blocks against argument values, over all decoded variants.
// Matching propagates BOTH labels independently:
//   - any matched untrusted block  -> argument integrity-tainted
//   - any matched high block       -> argument confidentiality-high
type Matcher struct {
	// TokenLen is the minimum token length for the fuzzy long-token rule.
	// Long alphanumeric runs are high-entropy identifiers/secrets; a hit on
	// one of them is strong evidence of copying. Over-matching biases toward
	// challenges (fail-safe), under-matching toward misses — the default is
	// deliberately conservative.
	TokenLen int
}

func NewMatcher() *Matcher { return &Matcher{TokenLen: 12} }

// Matches returns the blocks contained in (or containing) any decoded
// variant of arg. Order is stable: block order.
func (m *Matcher) Matches(arg string, blocks []Block) []Match {
	tl := m.TokenLen
	if tl <= 0 {
		tl = 12
	}
	var variants []string
	for _, v := range Decodings(arg) {
		variants = append(variants, v, NormalizeForMatch(v))
	}
	argTokens := longTokens(arg, tl)
	seen := map[string]bool{}
	var out []Match
	for _, b := range blocks {
		if seen[b.ID] {
			continue
		}
		hit, exact := m.blockHit(b.Text, variants, argTokens, tl)
		if hit {
			seen[b.ID] = true
			out = append(out, Match{BlockID: b.ID, Exact: exact})
		}
	}
	return out
}

// minSpan is the minimum containment length for exact matching. Without it,
// tiny arguments ("make", "42") would match nearly every block and the gate
// would challenge everything (fail-safe but useless). Short secrets are
// still caught by the fuzzy token rule and the classifier.
const minSpan = 8

func (m *Matcher) blockHit(text string, variants []string, argTokens map[string]bool, tl int) (bool, bool) {
	if text == "" {
		return false, false
	}
	norm := NormalizeForMatch(text)
	// exact: block text appears inside any argument variant (block pasted
	// into the arg), or the variant appears inside the block (arg quoted from
	// the block) — both directions need a meaningful span.
	for _, v := range variants {
		if len(text) >= minSpan && strings.Contains(v, text) {
			return true, true
		}
		if len(v) >= minSpan && strings.Contains(text, v) {
			return true, true
		}
		if norm != "" && len(norm) >= minSpan && strings.Contains(v, norm) {
			return true, true
		}
	}
	// fuzzy: any long high-entropy token from the block shows up in the
	// argument (reworded injections that carry identifiers still match).
	for _, t := range longTokens(text, tl) {
		if argTokens[t] {
			return true, false
		}
	}
	return false, false
}

// longTokens extracts alphanumeric runs of at least minLen characters,
// lowercased, as a set.
func longTokens(s string, minLen int) map[string]bool {
	out := map[string]bool{}
	var cur strings.Builder
	flush := func() {
		if cur.Len() >= minLen {
			out[cur.String()] = true
		}
		cur.Reset()
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			cur.WriteRune(unicode.ToLower(r))
		} else {
			flush()
		}
	}
	flush()
	return out
}
