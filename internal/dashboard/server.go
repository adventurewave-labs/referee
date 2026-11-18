// Package dashboard is the minimal in-binary operator surface (PRD §6):
// live sessions, decision log, receipt viewer, verify status, and the local
// challenge approver. Full detail requires the dashboard token; receipts are
// HMAC-only so the log view never shows secrets (§5.4).
package dashboard

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/adventurewave-labs/referee/internal/challenge"
	"github.com/adventurewave-labs/referee/internal/receipts"
)

// Deps wires the dashboard to the running engine.
type Deps struct {
	LogPath      string
	HeadsPath    string
	PubKey       []byte // ed25519 public key for verify
	Token        string // required for approve + full detail
	ReceiptsKey  []byte
	Challenges   *challenge.Manager
	Sessions func() []SessionInfo
}

// SessionInfo is one live session snapshot.
type SessionInfo struct {
	ID       string
	TaskID   string
	Class    string
	Blocks   int
	Untrusted int
	Alive    bool
}

// Server is the dashboard HTTP server.
type Server struct {
	deps Deps
}

func New(deps Deps) *Server { return &Server{deps: deps} }

// Handler returns the mux. POST /slack/interactive is registered separately
// by the serve command when Slack is configured.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.index)
	mux.HandleFunc("/api/decisions", s.apiDecisions)
	mux.HandleFunc("/api/sessions", s.apiSessions)
	mux.HandleFunc("/api/challenges", s.apiChallenges)
	mux.HandleFunc("/api/challenge/", s.apiResolve)
	mux.HandleFunc("/api/verify", s.apiVerify)
	return mux
}

func (s *Server) authed(r *http.Request) bool {
	if s.deps.Token == "" {
		return false
	}
	h := r.Header.Get("Authorization")
	return h == "Bearer "+s.deps.Token
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	var sb strings.Builder
	sb.WriteString(`<!doctype html><html><head><title>referee</title><style>
body{font-family:-apple-system,sans-serif;margin:2rem;background:#0d1117;color:#c9d1d9}
table{border-collapse:collapse;margin:1rem 0}td,th{border:1px solid #30363d;padding:.35rem .7rem;font-size:.9rem}
h2{color:#58a6ff;margin-top:2rem}.approve{color:#3fb950}.deny{color:#f85149}.challenge{color:#d29922}
code{color:#79c0ff}</style></head><body><h1>🛡 referee</h1>`)

	sb.WriteString("<h2>live sessions</h2><table><tr><th>session</th><th>task</th><th>class</th><th>blocks</th><th>untrusted</th><th>token</th></tr>")
	if s.deps.Sessions != nil {
		for _, si := range s.deps.Sessions() {
			state := "alive"
			if !si.Alive {
				state = "dead"
			}
			fmt.Fprintf(&sb, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%s</td></tr>",
				html.EscapeString(si.ID), html.EscapeString(si.TaskID), html.EscapeString(si.Class), si.Blocks, si.Untrusted, state)
		}
	}
	sb.WriteString("</table>")

	sb.WriteString("<h2>pending challenges</h2><table><tr><th>id</th><th>tool</th><th>rule</th><th>deadline</th></tr>")
	if s.deps.Challenges != nil {
		for _, c := range s.deps.Challenges.Pending() {
			fmt.Fprintf(&sb, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				html.EscapeString(c.ID), html.EscapeString(c.Tool), html.EscapeString(c.Rule), c.Deadline.Format(time.Kitchen))
		}
	}
	sb.WriteString("</table>")

	sb.WriteString("<h2>recent decisions (HMAC-only receipts)</h2><table><tr><th>seq</th><th>time</th><th>task</th><th>tool</th><th>decision</th><th>rule</th><th>approver</th><th>axis</th></tr>")
	entries, err := receipts.ReadAll(s.deps.LogPath)
	if err == nil {
		start := 0
		if len(entries) > 25 {
			start = len(entries) - 25
		}
		for _, e := range entries[start:] {
			cls := ""
			switch e.Decision {
			case "deny":
				cls = "deny"
			case "approve":
				cls = "approve"
			case "challenge":
				cls = "challenge"
			}
			fmt.Fprintf(&sb, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td class=%q>%s</td><td><code>%s</code></td><td>%s</td><td><code>%s</code></td></tr>",
				e.Seq, e.TS.Format("15:04:05"), html.EscapeString(e.Task), html.EscapeString(e.Tool), cls, e.Decision,
				html.EscapeString(e.Rule), html.EscapeString(e.Approver), html.EscapeString(e.Axis))
		}
	}
	sb.WriteString("</table>")
	sb.WriteString(`<p>API: <code>/api/decisions</code> · <code>/api/sessions</code> · <code>/api/challenges</code> · <code>/api/verify</code> · approve via <code>POST /api/challenge/&lt;id&gt;/resolve</code> (Bearer token)</p>`)
	sb.WriteString("</body></html>")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(sb.String()))
}

func (s *Server) apiDecisions(w http.ResponseWriter, r *http.Request) {
	entries, err := receipts.ReadAll(s.deps.LogPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	limit := 100
	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	writeJSON(w, entries)
}

func (s *Server) apiSessions(w http.ResponseWriter, r *http.Request) {
	var out []SessionInfo
	if s.deps.Sessions != nil {
		out = s.deps.Sessions()
	}
	writeJSON(w, out)
}

func (s *Server) apiChallenges(w http.ResponseWriter, r *http.Request) {
	var out []challenge.Challenge
	if s.deps.Challenges != nil {
		out = s.deps.Challenges.Pending()
	}
	writeJSON(w, out)
}

// apiResolve is the local approver path: POST /api/challenge/<id>/resolve
// with {"approver": "...", "approve": true|false} and the Bearer token.
func (s *Server) apiResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !s.authed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/challenge/"), "/")
	if len(parts) != 2 || parts[1] != "resolve" {
		http.Error(w, "bad path", http.StatusNotFound)
		return
	}
	var body struct {
		Approver string `json:"approver"`
		Approve  bool   `json:"approve"`
	}
	if err := readJSON(r, &body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.deps.Challenges == nil {
		http.Error(w, "no challenge manager", http.StatusInternalServerError)
		return
	}
	if err := s.deps.Challenges.Resolve(parts[0], body.Approver, body.Approve); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) apiVerify(w http.ResponseWriter, r *http.Request) {
	var pub []byte
	if s.authed(r) {
		pub = s.deps.PubKey
	}
	n, heads, err := receipts.Verify(s.deps.LogPath, s.deps.HeadsPath, pub)
	out := map[string]any{"entries": n, "heads_verified": heads, "ok": err == nil, "heads_checked": pub != nil}
	if err != nil {
		out["error"] = err.Error()
	}
	writeJSON(w, out)
}

func writeJSON(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
