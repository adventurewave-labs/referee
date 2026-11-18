// Package labels implements the Referee label model (PRD §5.1): every content
// block entering the agent context carries (block-id, source, trust,
// sensitivity, timestamp). The two labels are independent and are never
// conflated: a trusted-but-high-sensitivity block (an operator-provided
// credential) is exfiltration-relevant but not injection-relevant.
package labels

import (
	"fmt"
	"time"
)

// Trust is the integrity axis label.
type Trust string

const (
	TrustTrusted   Trust = "trusted"
	TrustSemi      Trust = "semi-trusted"
	TrustUntrusted Trust = "untrusted"
)

// Sensitivity is the confidentiality axis label.
type Sensitivity string

const (
	SensNormal Sensitivity = "normal"
	SensHigh   Sensitivity = "high"
)

// Higher reports whether a is strictly more sensitive than required by b.
// A cap covers a call when cap.Sensitivity >= call sensitivity; SensHigh
// calls can only be covered by SensHigh caps.
func (s Sensitivity) Covers(other Sensitivity) bool {
	if other == SensHigh {
		return s == SensHigh
	}
	return true // normal calls are covered by both normal and high caps
}

// Block is one ingested content block (the normative tag schema, §5.1).
type Block struct {
	ID          string      // unique id of this ingested block, e.g. "b-0007"
	Source      string      // "operator", "user", "tool:<name>", "web", "rag", "file:<path>"
	Trust       Trust       // integrity label
	Sensitivity Sensitivity // confidentiality label
	IngestedAt  time.Time   // ingestion time
	Text        string      // content; stays in the shadow context, never in receipts
}

// Untrusted reports whether the block is integrity-tainting.
func (b Block) Untrusted() bool { return b.Trust == TrustUntrusted }

// High reports whether the block is confidentiality-relevant.
func (b Block) High() bool { return b.Sensitivity == SensHigh }

func (b Block) String() string {
	return fmt.Sprintf("%s[source=%s trust=%s sens=%s]", b.ID, b.Source, b.Trust, b.Sensitivity)
}
