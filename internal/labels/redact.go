package labels

import (
	"fmt"
	"sort"
	"strings"
)

// RedactMode is the per-tool argument-sanitization policy (PRD §6 P1
// "redaction path"): none (default — gate as usual), strip (remove
// matched segments), mask (replace matched segments with ▒).
type RedactMode string

const (
	RedactNone RedactMode = "none"
	RedactStrip RedactMode = "strip"
	RedactMask  RedactMode = "mask"
)

// ValidRedactMode reports whether a policy value is legal.
func ValidRedactMode(m RedactMode) bool {
	switch m {
	case RedactNone, RedactStrip, RedactMask, "":
		return true
	}
	return false
}

// RedactValue sanitizes ONE argument value against the blocks whose content
// influenced it (already selected by the containment matcher) plus the
// classifier's credential shapes. Returns the sanitized value and whether it
// changed. Honest scope (v1):
//   - literal block-text spans (case-insensitive) are removed/masked in place;
//   - long-token spans (≥ matcher token length) from matched blocks likewise —
//     identifiers survive rewording, so they are stripped wherever they sit;
//   - classifier-shaped spans (credentials) are stripped/masked;
//   - an ENCODED embedding (a decoded variant contains block text but no
//     literal span exists) cannot be localized inside the encoding safely —
//     the whole value is withheld (strip → "", mask → full mask).
func RedactValue(value string, matched []Block, mode RedactMode, classifier *Classifier, tokenLen int) (string, bool) {
	if mode == RedactNone || value == "" {
		return value, false
	}
	lower := strings.ToLower(value)
	type span struct{ start, end int }
	var spans []span
	addSpan := func(start, end int) {
		if start < 0 || end > len(value) || start >= end {
			return
		}
		spans = append(spans, span{start, end})
	}
	encodedHit := false

	for _, b := range matched {
		text := strings.TrimSpace(b.Text)
		if text == "" {
			continue
		}
		// literal span (case-insensitive)
		if i := strings.Index(lower, strings.ToLower(text)); i >= 0 {
			addSpan(i, i+len(text))
			continue
		}
		// long-token spans from the block
		hit := false
		for tok := range longTokens(text, tokenLen) {
			for i := 0; i+len(tok) <= len(lower); {
				j := strings.Index(lower[i:], tok)
				if j < 0 {
					break
				}
				addSpan(i+j, i+j+len(tok))
				i += j + len(tok)
				hit = true
			}
		}
		if hit {
			continue
		}
		// encoded embedding: a decoded variant carries the block text but no
		// localizable literal span — withhold the whole value
		for _, v := range Decodings(value) {
			if strings.Contains(strings.ToLower(v), strings.ToLower(text)) {
				encodedHit = true
				break
			}
		}
	}
	// classifier-shaped spans (credential shapes) — the classifier itself is
	// the shipped backstop for secrets the labels never saw
	for _, re := range classifier.Patterns {
		for _, loc := range re.FindAllStringIndex(value, -1) {
			addSpan(loc[0], loc[1])
		}
	}
	if highEntropyRun(value) {
		// an entropy run cannot be localized by the shipped patterns; withhold
		// the whole value rather than guess at spans
		encodedHit = true
	}

	if encodedHit {
		if mode == RedactStrip {
			return "", true
		}
		return strings.Repeat("▒", minInt(len(value), 12)) + fmt.Sprintf(" (len=%d, withheld)", len(value)), true
	}
	if len(spans) == 0 {
		return value, false
	}
	// merge overlapping spans, then rebuild
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var merged []span
	for _, sp := range spans {
		if last := len(merged) - 1; last >= 0 && sp.start <= merged[last].end {
			if sp.end > merged[last].end {
				merged[last].end = sp.end
			}
			continue
		}
		merged = append(merged, sp)
	}
	var b strings.Builder
	prev := 0
	for _, sp := range merged {
		b.WriteString(value[prev:sp.start])
		if mode == RedactStrip {
			// nothing: the segment is removed
		} else {
			b.WriteString(strings.Repeat("▒", sp.end-sp.start))
		}
		prev = sp.end
	}
	b.WriteString(value[prev:])
	return b.String(), true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
