package proxy

import (
	"fmt"
	"sync"
	"time"

	"github.com/adventurewave-labs/referee/internal/labels"
	"github.com/adventurewave-labs/referee/internal/policy"
)

// Session is one agent session's shadow context: every content block that
// entered the agent's world through Referee, tagged per the label model
// (§5.1). stdio mode runs one session per process; HTTP mode keeps a map by
// MCP session id.
type Session struct {
	ID string

	mu      sync.Mutex
	blocks  []labels.Block
	counter int

	TaskID    string
	TaskClass string

	registry *labels.Registry
}

func NewSession(id string, registry *labels.Registry) *Session {
	return &Session{ID: id, registry: registry}
}

// AddBlock ingests content with explicit labels (operator/user blocks).
func (s *Session) AddBlock(source string, trust labels.Trust, sens labels.Sensitivity, text string) labels.Block {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counter++
	b := labels.Block{
		ID:          fmt.Sprintf("b-%04d", s.counter),
		Source:      source,
		Trust:       trust,
		Sensitivity: sens,
		IngestedAt:  time.Now().UTC(),
		Text:        text,
	}
	s.blocks = append(s.blocks, b)
	return b
}

// AddOperator ingests an operator-provided block (trusted per the registry).
func (s *Session) AddOperator(text string) labels.Block {
	t, sens := s.registry.ForKind(labels.KindOperator)
	return s.AddBlock("operator", t, sens, text)
}

// AddUser ingests a user-message block (semi-trusted per the registry).
func (s *Session) AddUser(text string) labels.Block {
	t, sens := s.registry.ForKind(labels.KindUser)
	return s.AddBlock("user", t, sens, text)
}

// IngestToolResult captures a tools/call result into the shadow context,
// labeling by the tool's declared emission class (PRD §5.1 sources):
// tool-result (untrusted), web/rag (untrusted), file-read (trust AND
// sensitivity by path policy — secrets dirs label content high).
func (s *Session) IngestToolResult(tool *policy.Tool, path string, text string) labels.Block {
	if text == "" {
		return labels.Block{}
	}
	kind := labels.KindToolResult
	switch tool.Emits {
	case "web":
		kind = labels.KindWeb
	case "rag":
		kind = labels.KindRAG
	case "file-read":
		kind = labels.KindFile
	}
	var trust labels.Trust
	var sens labels.Sensitivity
	if kind == labels.KindFile {
		trust, sens = s.registry.ForPath(labels.NormalizePath(path))
	} else {
		trust, sens = s.registry.ForKind(kind)
	}
	source := "tool:" + tool.Name
	switch kind {
	case labels.KindWeb:
		source = "web:" + tool.Name
	case labels.KindRAG:
		source = "rag:" + tool.Name
	case labels.KindFile:
		source = "file:" + path
	}
	return s.AddBlock(source, trust, sens, text)
}

// Snapshot returns a copy of the current shadow context.
func (s *Session) Snapshot() []labels.Block {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]labels.Block, len(s.blocks))
	copy(out, s.blocks)
	return out
}

// UntrustedCount is the number of untrusted blocks in the shadow context —
// the probe runs only while untrusted content exists.
func (s *Session) UntrustedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, b := range s.blocks {
		if b.Untrusted() {
			n++
		}
	}
	return n
}
