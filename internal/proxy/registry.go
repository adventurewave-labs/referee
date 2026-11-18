package proxy

import (
	"sync"
)

// SessionStat is the dashboard-facing snapshot of one session.
type SessionStat struct {
	ID        string
	TaskID    string
	Class     string
	Blocks    int
	Untrusted int
	Alive     bool // token alive
}

// Registry tracks live sessions for the dashboard.
type Registry struct {
	mu       sync.Mutex
	sessions []*Session
	alive    func(taskID string) bool // optional token-aliveness check
}

func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) Add(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions = append(r.sessions, s)
}

// WithAlive wires the token-aliveness check (caps store lookup).
func (r *Registry) WithAlive(f func(taskID string) bool) { r.alive = f }

// Stats snapshots all live sessions.
func (r *Registry) Stats() []SessionStat {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]SessionStat, 0, len(r.sessions))
	for _, s := range r.sessions {
		snap := s.Snapshot()
		un := 0
		for _, b := range snap {
			if b.Untrusted() {
				un++
			}
		}
		alive := false
		if s.TaskID != "" && r.alive != nil {
			alive = r.alive(s.TaskID)
		}
		out = append(out, SessionStat{
			ID: s.ID, TaskID: s.TaskID, Class: s.TaskClass,
			Blocks: len(snap), Untrusted: un, Alive: alive,
		})
	}
	return out
}
