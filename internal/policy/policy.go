// Package policy implements the Referee policy DSL (PRD §5.2/§5.3): a YAML,
// capability-style language — deliberately not Turing-complete — compiled
// into the two-axis verbs, task classes with sensitivity-bearing caps,
// approver allowlists, and judge configuration the gate consumes.
package policy

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"os"
	"time"

	"github.com/adventurewave-labs/referee/internal/labels"
	"gopkg.in/yaml.v3"
)

// IntegrityVerb — per-tool integrity axis verb (§5.3).
type IntegrityVerb string

const (
	TrustAny           IntegrityVerb = "trust-any"
	ChallengeIfTainted IntegrityVerb = "challenge-if-tainted"
	RequireTrusted     IntegrityVerb = "require-trusted"
)

// ConfVerb — per-tool confidentiality axis verb (§5.3).
type ConfVerb string

const (
	SensitivityAny  ConfVerb = "sensitivity-any"
	ChallengeIfHigh ConfVerb = "challenge-if-high"
	RequireNormal   ConfVerb = "require-normal"
)

// Dur is a YAML-friendly time.Duration ("4h", "15m", "30s").
type Dur time.Duration

func (d *Dur) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	dd, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("policy: bad duration %q: %w", s, err)
	}
	*d = Dur(dd)
	return nil
}

func (d Dur) D() time.Duration { return time.Duration(d) }

// Defaults are operator-level guardrails.
type Defaults struct {
	TTL          Dur `yaml:"ttl"`
	TTLCeiling   Dur `yaml:"ttl_ceiling"`
	ProbeTimeout Dur `yaml:"probe_timeout"`
}

// PathRuleYAML labels file reads under a glob (trust AND sensitivity).
type PathRuleYAML struct {
	Pattern     string             `yaml:"pattern"`
	Trust       labels.Trust       `yaml:"trust"`
	Sensitivity labels.Sensitivity `yaml:"sensitivity"`
}

// Tool declares one tool's gate configuration.
type Tool struct {
	Name            string        `yaml:"name"`
	Integrity       IntegrityVerb `yaml:"integrity"`
	Confidentiality ConfVerb      `yaml:"confidentiality"`
	Approvers       []string      `yaml:"approvers"`
	CapGapChallenge bool          `yaml:"cap_gap_challenge"`
	ProbeConsensus  bool          `yaml:"probe_consensus"`
	Emits           string        `yaml:"emits"`         // tool-result|web|rag|file-read
	EmitPathArg     string        `yaml:"emit_path_arg"` // for file-read: arg carrying the path
	SinkClass       string        `yaml:"sink_class"`    // probe cache dimension; default = tool name
	Redact          string        `yaml:"redact"`        // none|strip|mask — auto-sanitize tainted/high args where the re-gate clears (PRD §6 P1)
}

// CapDecl is one sensitivity-bearing capability (§5.2): a cap covers calls up
// to its declared sensitivity; a normal-sensitivity cap never authorizes a
// high call.
type CapDecl struct {
	Tool        string             `yaml:"tool"`
	ScopeArg    string             `yaml:"scope_arg"`
	Pattern     string             `yaml:"pattern"`
	Sensitivity labels.Sensitivity `yaml:"sensitivity"`
}

// Key identifies a cap for narrowing manifests.
func (c CapDecl) Key() string { return c.Tool + "|" + c.Pattern }

// TaskClass is a named task shape: caps + TTL, minted at task start from the
// operator's policy only (harness manifests may narrow, never widen).
type TaskClass struct {
	Class string    `yaml:"class"`
	TTL   Dur       `yaml:"ttl"`
	Caps  []CapDecl `yaml:"caps"`
}

// JudgeCfg configures one influence-probe judge.
type JudgeCfg struct {
	Name      string `yaml:"name"`
	Provider  string `yaml:"provider"` // openai|anthropic|mock
	Model     string `yaml:"model"`
	Endpoint  string `yaml:"endpoint"`
	APIKeyEnv string `yaml:"api_key_env"`
}

// File is the on-disk YAML shape.
type File struct {
	Version  int            `yaml:"version"`
	Defaults Defaults       `yaml:"defaults"`
	Paths    []PathRuleYAML `yaml:"paths"`
	Tools    []Tool         `yaml:"tools"`
	Tasks    []TaskClass    `yaml:"tasks"`
	Judges   []JudgeCfg     `yaml:"judges"`
}

// Policy is the compiled form the gate consumes.
type Policy struct {
	Defaults Defaults
	Registry *labels.Registry
	Tools    map[string]*Tool
	Tasks    map[string]*TaskClass
	Judges   []JudgeCfg
	Source   *File
}

// Valid verbs for validation.
var validIntegrity = map[IntegrityVerb]bool{TrustAny: true, ChallengeIfTainted: true, RequireTrusted: true}
var validConf = map[ConfVerb]bool{SensitivityAny: true, ChallengeIfHigh: true, RequireNormal: true}
var validSens = map[labels.Sensitivity]bool{labels.SensNormal: true, labels.SensHigh: true}
var validEmits = map[string]bool{"tool-result": true, "web": true, "rag": true, "file-read": true}

// Compile validates and compiles a policy file into a Policy.
func Compile(f *File) (*Policy, error) {
	if f.Version != 1 {
		return nil, fmt.Errorf("policy: unsupported version %d (want 1)", f.Version)
	}
	p := &Policy{
		Defaults: f.Defaults,
		Registry: labels.Default(),
		Tools:    map[string]*Tool{},
		Tasks:    map[string]*TaskClass{},
		Judges:   f.Judges,
		Source:   f,
	}
	// defaults: TTL ceiling mandatory floor of 1m; default TTL must not exceed ceiling
	if p.Defaults.TTLCeiling.D() <= 0 {
		p.Defaults.TTLCeiling = Dur(4 * time.Hour)
	}
	if p.Defaults.TTL.D() <= 0 {
		p.Defaults.TTL = Dur(4 * time.Hour)
	}
	if p.Defaults.TTL.D() > p.Defaults.TTLCeiling.D() {
		p.Defaults.TTL = p.Defaults.TTLCeiling
	}
	if p.Defaults.ProbeTimeout.D() <= 0 {
		p.Defaults.ProbeTimeout = Dur(8 * time.Second)
	}

	for _, r := range f.Paths {
		if r.Pattern == "" {
			return nil, fmt.Errorf("policy: path rule with empty pattern")
		}
		trust := r.Trust
		if trust == "" {
			trust = labels.TrustUntrusted
		}
		sens := r.Sensitivity
		if sens == "" {
			sens = labels.SensNormal
		}
		if !validSens[sens] {
			return nil, fmt.Errorf("policy: path %q bad sensitivity %q", r.Pattern, sens)
		}
		if trust != labels.TrustTrusted && trust != labels.TrustSemi && trust != labels.TrustUntrusted {
			return nil, fmt.Errorf("policy: path %q bad trust %q", r.Pattern, trust)
		}
		p.Registry.PathRules = append(p.Registry.PathRules, labels.PathRule{
			Pattern: r.Pattern, Trust: trust, Sensitivity: sens,
		})
	}

	for i := range f.Tools {
		t := f.Tools[i]
		if t.Name == "" {
			return nil, fmt.Errorf("policy: tool with empty name")
		}
		if _, dup := p.Tools[t.Name]; dup {
			return nil, fmt.Errorf("policy: duplicate tool %q", t.Name)
		}
		if t.Integrity == "" {
			t.Integrity = ChallengeIfTainted
		}
		if t.Confidentiality == "" {
			t.Confidentiality = ChallengeIfHigh
		}
		if !validIntegrity[t.Integrity] {
			return nil, fmt.Errorf("policy: tool %q bad integrity verb %q", t.Name, t.Integrity)
		}
		if !validConf[t.Confidentiality] {
			return nil, fmt.Errorf("policy: tool %q bad confidentiality verb %q", t.Name, t.Confidentiality)
		}
		if t.Emits != "" && !validEmits[t.Emits] {
			return nil, fmt.Errorf("policy: tool %q bad emits %q", t.Name, t.Emits)
		}
		if t.Emits == "file-read" && t.EmitPathArg == "" {
			return nil, fmt.Errorf("policy: tool %q emits file-read but no emit_path_arg", t.Name)
		}
		if t.SinkClass == "" {
			t.SinkClass = t.Name
		}
		if !labels.ValidRedactMode(labels.RedactMode(t.Redact)) {
			return nil, fmt.Errorf("policy: tool %q bad redact %q (none|strip|mask)", t.Name, t.Redact)
		}
		if t.Redact == "" {
			t.Redact = string(labels.RedactNone) // explicit default: empty must never act as "enabled"
		}
		p.Tools[t.Name] = &t
	}

	for i := range f.Tasks {
		tc := f.Tasks[i]
		if tc.Class == "" {
			return nil, fmt.Errorf("policy: task class with empty name")
		}
		if _, dup := p.Tasks[tc.Class]; dup {
			return nil, fmt.Errorf("policy: duplicate task class %q", tc.Class)
		}
		if tc.TTL.D() <= 0 {
			tc.TTL = p.Defaults.TTL
		}
		if tc.TTL.D() > p.Defaults.TTLCeiling.D() {
			tc.TTL = p.Defaults.TTLCeiling // clamp, never widen past ceiling
		}
		for j, c := range tc.Caps {
			if c.Tool == "" {
				return nil, fmt.Errorf("policy: task %q cap %d missing tool", tc.Class, j)
			}
			if c.Sensitivity == "" {
				c.Sensitivity = labels.SensNormal
			}
			if !validSens[c.Sensitivity] {
				return nil, fmt.Errorf("policy: task %q cap %d bad sensitivity %q", tc.Class, j, c.Sensitivity)
			}
			if c.Pattern == "" {
				c.Pattern = "*"
			}
			tc.Caps[j] = c
		}
		p.Tasks[tc.Class] = &tc
	}
	return p, nil
}

// Load reads and compiles a policy file.
func Load(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	var f File
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return Compile(&f)
}

// ToolFor returns the declared tool config or strict defaults for undeclared
// tools (undeclared tools still need a cap, and cap-gap-challenge is opt-in,
// so undeclared tools are deny-by-default at the capability check).
func (p *Policy) ToolFor(name string) *Tool {
	if t, ok := p.Tools[name]; ok {
		return t
	}
	return &Tool{Name: name, Integrity: ChallengeIfTainted, Confidentiality: ChallengeIfHigh, SinkClass: name,
		Redact: string(labels.RedactNone)}
}

// NarrowCaps implements the manifest-narrowing rule (§5.2): the harness may
// request cap names for a task class, but the minted caps are always the
// policy's own declarations — requested names must exist in the class and the
// result can only be a subset, never wider.
func (p *Policy) NarrowCaps(class string, requested []string) ([]CapDecl, error) {
	tc, ok := p.Tasks[class]
	if !ok {
		return nil, fmt.Errorf("policy: unknown task class %q", class)
	}
	if len(requested) == 0 {
		out := make([]CapDecl, len(tc.Caps))
		copy(out, tc.Caps)
		return out, nil
	}
	byKey := map[string]CapDecl{}
	for _, c := range tc.Caps {
		byKey[c.Key()] = c
	}
	var out []CapDecl
	seen := map[string]bool{}
	for _, r := range requested {
		c, ok := byKey[r]
		if !ok {
			return nil, fmt.Errorf("policy: task %q does not grant cap %q (manifests narrow, never widen)", class, r)
		}
		if !seen[r] {
			out = append(out, c)
			seen[r] = true
		}
	}
	return out, nil
}

// Hash returns a stable SHA-256 over the compiled policy's source — used by
// observe to bind receipt analysis to the policy that produced the receipts
// (round-77: suggestions must reference the grants of THIS policy).
func (p *Policy) Hash() string {
	h := sha256.New()
	// canonical basis: version + defaults + every declared element, in order
	fmt.Fprintf(h, "v%d|ttl=%s|ceiling=%s|probe=%s\n", p.Source.Version,
		p.Source.Defaults.TTL.D(), p.Source.Defaults.TTLCeiling.D(), p.Source.Defaults.ProbeTimeout.D())
	for _, r := range p.Source.Paths {
		fmt.Fprintf(h, "path|%s|%s|%s\n", r.Pattern, r.Trust, r.Sensitivity)
	}
	names := make([]string, 0, len(p.Tools))
	for n := range p.Tools {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		t := p.Tools[n]
		fmt.Fprintf(h, "tool|%s|%s|%s|redact=%s|emits=%s|epa=%s|sink=%s|gap=%t|cons=%t|approvers=%v\n",
			t.Name, t.Integrity, t.Confidentiality, t.Redact, t.Emits, t.EmitPathArg,
			t.SinkClass, t.CapGapChallenge, t.ProbeConsensus, t.Approvers)
	}
	classes := make([]string, 0, len(p.Tasks))
	for c := range p.Tasks {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	for _, c := range classes {
		tc := p.Tasks[c]
		fmt.Fprintf(h, "task|%s|ttl=%s\n", tc.Class, tc.TTL.D())
		for _, cap := range tc.Caps {
			fmt.Fprintf(h, "cap|%s|%s|%s|%s\n", cap.Tool, cap.ScopeArg, cap.Pattern, cap.Sensitivity)
		}
	}
	for _, j := range p.Judges {
		fmt.Fprintf(h, "judge|%s|%s|%s|%s\n", j.Name, j.Provider, j.Model, j.Endpoint)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
