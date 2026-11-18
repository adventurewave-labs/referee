// Package tuning implements the probe tuning loop (PRD §6 P1): a paired-
// replay corpus (methodology per arXiv:2610.05840) replayed through the full
// gate — containment, probe, caps — measuring the §8 product-truth metrics:
// ≥85% of injection-driven gated calls challenged/denied (recall), ≤5%
// false-challenge rate on clean traces. Pairs replay the same task twice:
// once clean, once with the injection present, so divergence is visible.
package tuning

import (
	"fmt"
	"os"

	"github.com/adventurewave-labs/referee/internal/labels"
	"gopkg.in/yaml.v3"
)

// Expectation of a case.
const (
	ExpectApprove          = "approve"            // clean trace: must auto-approve
	ExpectChallengeOrDeny  = "challenge-or-deny"  // injected trace: must gate
)

// CaseBlock is one labeled block in a case's shadow context.
type CaseBlock struct {
	Trust       labels.Trust       `yaml:"trust"`
	Sensitivity labels.Sensitivity `yaml:"sensitivity"`
	Source      string             `yaml:"source"`
	Text        string             `yaml:"text"`
}

// Case is one replay: a tool call against a shadow context with an expected
// gate outcome. Pairs share a Pair name; the clean/injected halves diverge
// only in the injection-bearing blocks/arguments.
type Case struct {
	Name    string         `yaml:"name"`
	Pair    string         `yaml:"pair,omitempty"` // paired-replay grouping
	Kind    string         `yaml:"kind"`           // "clean" | "injected"
	Tool    string         `yaml:"tool"`
	Args    map[string]any `yaml:"args"`
	Blocks  []CaseBlock    `yaml:"blocks"`
	Expect  string         `yaml:"expect"`
	Note    string         `yaml:"note,omitempty"`
}

// Corpus is a YAML tuning corpus.
type Corpus struct {
	Description string `yaml:"description"`
	Cases       []Case `yaml:"cases"`
}

// LoadCorpus reads a corpus file.
func LoadCorpus(path string) (*Corpus, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tuning: %w", err)
	}
	var c Corpus
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("tuning: bad corpus: %w", err)
	}
	if len(c.Cases) == 0 {
		return nil, fmt.Errorf("tuning: corpus %s has no cases", path)
	}
	for i, cs := range c.Cases {
		switch cs.Expect {
		case ExpectApprove, ExpectChallengeOrDeny:
		default:
			return nil, fmt.Errorf("tuning: case %d (%s): expect must be %q or %q", i, cs.Name, ExpectApprove, ExpectChallengeOrDeny)
		}
		switch cs.Kind {
		case "clean", "injected":
		default:
			return nil, fmt.Errorf("tuning: case %d (%s): kind must be clean|injected", i, cs.Name)
		}
	}
	return &c, nil
}

// ToBlocks converts corpus blocks into the engine's label model.
func (cs Case) ToBlocks() []labels.Block {
	out := make([]labels.Block, 0, len(cs.Blocks))
	for i, b := range cs.Blocks {
		out = append(out, labels.Block{
			ID:          fmt.Sprintf("t-%s-%03d", cs.Name, i),
			Source:      b.Source,
			Trust:       b.Trust,
			Sensitivity: b.Sensitivity,
			Text:        b.Text,
		})
	}
	return out
}
