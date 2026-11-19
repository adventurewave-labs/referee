package proxy

import (
	"bufio"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/adventurewave-labs/referee/internal/caps"
)

// TaskStartParams is the referee/task_start control shape (§5.2): the
// driving harness signals task boundaries explicitly. Manifests may only
// narrow the caps the policy grants the task class.
type TaskStartParams struct {
	TaskID          string   `json:"task_id"`
	TaskClass       string   `json:"task_class"`
	Caps            []string `json:"caps,omitempty"` // cap keys to narrow to
	OperatorContext string   `json:"operator_context,omitempty"`
	ControlToken    string   `json:"control_token"`
}

// controlAuthorized checks a privileged control RPC's token in constant time.
func controlAuthorized(e *Engine, token string) error {
	if len(e.ControlToken) == 0 {
		return fmt.Errorf("privileged control RPCs disabled (no control token configured; start tasks with serve --task-id or set REF_CONTROL_TOKEN)")
	}
	if subtle.ConstantTimeCompare([]byte(token), e.ControlToken) != 1 {
		return fmt.Errorf("control RPC refused: bad control token")
	}
	return nil
}

// RunStdio bridges one agent (on r) to one upstream MCP server (on upstream),
// intercepting tools/call through the Engine. Responses are written to w as
// newline-delimited JSON (the MCP stdio transport). One process == one
// session; the upstream process is spawned and owned by the caller.
func RunStdio(e *Engine, r io.Reader, w io.Writer, upstream io.ReadWriter) error {
	return RunStdioSession(e, NewSession("stdio", e.Policy.Registry), r, w, upstream)
}

// RunStdioSession is RunStdio on a caller-owned session, so a task started
// before the bridge runs (serve --task-id) binds to the session the calls use.
func RunStdioSession(e *Engine, sess *Session, r io.Reader, w io.Writer, upstream io.ReadWriter) error {

	agentIn := bufio.NewScanner(r)
	agentIn.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	upIn := bufio.NewReader(upstream)

	sendAgent := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			return err
		}
		return nil
	}

	respondErr := func(id json.RawMessage, code int, msg string) error {
		return sendAgent(Response{JSONRPC: "2.0", ID: id, Error: &RPCError{Code: code, Message: msg}})
	}

	for agentIn.Scan() {
		line := strings.TrimSpace(agentIn.Text())
		if line == "" {
			continue
		}
		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			// non-JSON line: cannot know an id; respond parse error with null id
			if err := respondErr(json.RawMessage("null"), CodeParseError, "parse error: not JSON"); err != nil {
				return err
			}
			continue
		}

		// -- Referee control plane (never forwarded upstream) --------------
		if strings.HasPrefix(req.Method, "referee/") {
			if err := handleControl(e, sess, &req, sendAgent); err != nil {
				if err := respondErr(req.ID, CodeInvalidParams, err.Error()); err != nil {
					return err
				}
			}
			continue
		}

		// -- notifications (no id): forward verbatim, no response expected --
		// Only MCP notifications/* may ride the id-less path: an id-less
		// tools/call (or any other request) would reach upstream ungated.
		if len(req.ID) == 0 {
			if !IsNotification(req.Method) {
				if e.Log != nil {
					e.Log.Printf("dropped id-less %q (only notifications/* forward without an id)", req.Method)
				}
				continue
			}
			line, err := json.Marshal(req)
			if err != nil {
				return err
			}
			if _, err := upstream.Write(append(line, '\n')); err != nil {
				return err
			}
			continue
		}

		// -- tools/call: the intercepted path -------------------------------
		if req.Method == "tools/call" {
			var params ToolCallParams
			if err := json.Unmarshal(req.Params, &params); err != nil {
				if err := respondErr(req.ID, CodeInvalidParams, "bad tools/call params"); err != nil {
					return err
				}
				continue
			}
			// forward exactly what the gate evaluated: re-serialize the parsed
			// params so duplicate/aliased keys that a lenient-vs-strict parser
			// differential could exploit never reach upstream (round-4)
			canonical, merr := json.Marshal(params)
			if merr != nil {
				if err := respondErr(req.ID, CodeInternalError, "bad tools/call params"); err != nil {
					return err
				}
				continue
			}
			req.Params = canonical
			result, forward, err := e.HandleToolCall(sess, params)
			if err != nil {
				if err := respondErr(req.ID, CodeInternalError, err.Error()); err != nil {
					return err
				}
				continue
			}
			if !forward {
				if err := sendAgent(DenyResponse(req.ID, result)); err != nil {
					return err
				}
				continue
			}
			// approved: forward upstream, capture the result into the shadow
			// context, then relay the response verbatim.
			upResp, err := roundTrip(upstream, upIn, req)
			if err != nil {
				if err := respondErr(req.ID, CodeInternalError, "upstream call failed: "+err.Error()); err != nil {
					return err
				}
				continue
			}
			e.IngestResult(sess, params, upResp.Result)
			if upResp.Error != nil {
				if eb, eberr := json.Marshal(upResp.Error); eberr == nil {
					e.IngestUpstream(sess, eb)
				}
			}
			if err := sendAgent(upResp); err != nil {
				return err
			}
			continue
		}

		// -- everything else: passthrough -----------------------------------
		resp, err := roundTrip(upstream, upIn, req)
		if err != nil {
			if err := respondErr(req.ID, CodeInternalError, "upstream error: "+err.Error()); err != nil {
				return err
			}
			continue
		}
		e.IngestResponse(sess, resp)
		if err := sendAgent(resp); err != nil {
			return err
		}
	}
	return agentIn.Err()
}

// roundTrip writes one request upstream and reads responses until the
// matching id arrives; notifications observed en route are dropped (logged).
func roundTrip(upstream io.Writer, upIn *bufio.Reader, req Request) (*Response, error) {
	line, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := upstream.Write(append(line, '\n')); err != nil {
		return nil, err
	}
	want := string(req.ID)
	for {
		l, err := upIn.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("upstream read: %w", err)
		}
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		var resp Response
		if err := json.Unmarshal([]byte(l), &resp); err != nil {
			continue // not a response line; skip
		}
		if string(resp.ID) == want {
			return &resp, nil
		}
		// notification or response for another id (sequential transport: none
		// expected) — skip
	}
}

// handleControl services referee/* methods: task_start, task_end, user_block,
// status. Control methods never touch upstream.
func handleControl(e *Engine, sess *Session, req *Request, send func(any) error) error {
	okResult := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		return send(Response{JSONRPC: "2.0", ID: req.ID, Result: b})
	}
	switch req.Method {
	case "referee/task_start":
		var p TaskStartParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return fmt.Errorf("bad task_start params: %w", err)
		}
		if err := controlAuthorized(e, p.ControlToken); err != nil {
			return err
		}
		if err := e.StartTask(sess, p.TaskID, p.TaskClass, p.Caps, p.OperatorContext); err != nil {
			return err
		}
		return okResult(map[string]any{"ok": true, "task": sess.TaskID, "class": sess.TaskClass})
	case "referee/task_end":
		killed := e.EndTask(sess)
		return okResult(map[string]any{"ok": true, "revoked": killed})
	case "referee/user_block":
		var p struct {
			Text         string `json:"text"`
			ControlToken string `json:"control_token"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return fmt.Errorf("bad user_block params: %w", err)
		}
		if err := controlAuthorized(e, p.ControlToken); err != nil {
			return err
		}
		sess.AddUser(p.Text)
		return okResult(map[string]any{"ok": true})
	case "referee/status":
		var tok *caps.Token
		if sess.TaskID != "" {
			tok = e.Caps.Get(sess.TaskID)
		}
		out := map[string]any{
			"session":          sess.ID,
			"task":             sess.TaskID,
			"class":            sess.TaskClass,
			"blocks":           len(sess.Snapshot()),
			"untrusted_blocks": sess.UntrustedCount(),
			"token_alive":      tok != nil,
		}
		return okResult(out)
	}
	return fmt.Errorf("unknown referee method %q", req.Method)
}

// SpawnUpstream starts an upstream MCP server command and returns its stdio
// pipe pair. Caller closes cmd's process.
func SpawnUpstream(cmdline string) (io.ReadWriteCloser, *exec.Cmd, error) {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return nil, nil, fmt.Errorf("empty upstream command")
	}
	cmd := exec.Command(fields[0], fields[1:]...)
	cmd.Env = UpstreamEnv(os.Environ())
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("spawn upstream %q: %w", fields[0], err)
	}
	rwc := &pipeRWC{r: stdout, w: stdin}
	return rwc, cmd, nil
}

type pipeRWC struct {
	r io.Reader
	w io.WriteCloser
}

func (p *pipeRWC) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeRWC) Write(x []byte) (int, error) { return p.w.Write(x) }
func (p *pipeRWC) Close() error                { return p.w.Close() }

// upstreamEnvAllowlist is the environment an upstream MCP server may see.
// Referee is a choke point holding judge keys, dashboard tokens, and receipt
// keys; upstream servers are untrusted (PRD §5.1) and inherit none of that
// by default (round-13, P1-6).
var upstreamEnvAllowlist = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true,
	"TMPDIR": true, "LANG": true, "TERM": true, "SHELL": true,
}

// UpstreamEnv builds the subprocess environment: the allowlist survives,
// everything else (REF_* secrets especially) is dropped.
func UpstreamEnv(inherited []string) []string {
	var out []string
	for _, kv := range inherited {
		if i := strings.IndexByte(kv, '='); i > 0 && upstreamEnvAllowlist[kv[:i]] {
			out = append(out, kv)
		}
	}
	return out
}
