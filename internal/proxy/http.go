package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// HTTPUpstream forwards streamable-HTTP MCP traffic to the real server.
// v1 speaks the JSON mode of the streamable-HTTP transport: one JSON-RPC
// message per POST, JSON response back. SSE streaming from upstream is a
// documented limitation (P1).
type HTTPUpstream struct {
	URL    string
	Client *http.Client
}

func (u *HTTPUpstream) RoundTrip(sessID string, req Request) (*Response, http.Header, error) {
	line, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}
	hreq, err := http.NewRequest(http.MethodPost, u.URL, bytes.NewReader(line))
	if err != nil {
		return nil, nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("Accept", "application/json")
	if sessID != "" {
		hreq.Header.Set("Mcp-Session-Id", sessID)
	}
	resp, err := u.Client.Do(hreq)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.Header, fmt.Errorf("upstream http %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var out Response
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, resp.Header, fmt.Errorf("upstream returned non-JSON (SSE mode unsupported in v1): %w", err)
	}
	return &out, resp.Header, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// RunHTTP serves the streamable-HTTP middleware on listen, forwarding to the
// upstream URL.
func RunHTTP(e *Engine, listen, upstreamURL string) error {
	return http.ListenAndServe(listen, HTTPHandler(e, upstreamURL))
}

// HTTPHandler builds the streamable-HTTP middleware handler. Sessions are
// keyed by the Mcp-Session-Id header (agent- or upstream-provided);
// referee/* control methods run locally per session.
func HTTPHandler(e *Engine, upstreamURL string) http.Handler {
	u := &HTTPUpstream{URL: upstreamURL, Client: &http.Client{}}
	var (
		mu       sync.Mutex
		sessions = map[string]*Session{}
		counter  int
	)

	sessionFor := func(id string) *Session {
		mu.Lock()
		defer mu.Unlock()
		s, ok := sessions[id]
		if !ok {
			counter++
			s = NewSession(fmt.Sprintf("http-%d", counter), e.Policy.Registry)
			sessions[id] = s
		}
		return s
	}

	writeJSON := func(w http.ResponseWriter, code int, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			http.Error(w, "marshal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		w.Write(b)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			// handled below
		case http.MethodGet, http.MethodDelete:
			// SSE stream / session teardown: not in v1 (documented limitation)
			http.Error(w, "Referee v1 supports JSON-mode POST /mcp only", http.StatusMethodNotAllowed)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		var req Request
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusOK, Response{JSONRPC: "2.0", ID: json.RawMessage("null"),
				Error: &RPCError{Code: CodeParseError, Message: "parse error: not JSON"}})
			return
		}
		sessID := r.Header.Get("Mcp-Session-Id")
		if sessID == "" {
			sessID = r.Header.Get("X-Referee-Session")
		}
		if sessID == "" {
			// agent did not carry a session id: use a per-connection id so the
			// shadow context still forms (documented: prefer sending the header)
			mu.Lock()
			counter++
			sessID = fmt.Sprintf("anon-%d", counter)
			mu.Unlock()
		}
		sess := sessionFor(sessID)

		if req.Method == "initialize" {
			resp, hdr, err := u.RoundTrip(sessID, req)
			if err != nil {
				writeJSON(w, http.StatusBadGateway, Response{JSONRPC: "2.0", ID: req.ID,
					Error: &RPCError{Code: CodeInternalError, Message: err.Error()}})
				return
			}
			if hs := hdr.Get("Mcp-Session-Id"); hs != "" {
				w.Header().Set("Mcp-Session-Id", hs)
				mu.Lock()
				if old := sess.ID; old != hs {
					sessions[hs] = sess
					delete(sessions, old)
					sess.ID = hs
				}
				mu.Unlock()
			}
			e.IngestResponse(sess, resp)
			writeJSON(w, http.StatusOK, resp)
			return
		}

		// referee control plane
		if strings.HasPrefix(req.Method, "referee/") {
			// handleControl emits the complete JSON-RPC response itself:
			// relay it as-is (wrapping it again would nest result.result)
			var out any
			if err := handleControl(e, sess, &req, func(v any) error {
				out = v
				return nil
			}); err != nil {
				writeJSON(w, http.StatusOK, Response{JSONRPC: "2.0", ID: req.ID,
					Error: &RPCError{Code: CodeInvalidParams, Message: err.Error()}})
				return
			}
			writeJSON(w, http.StatusOK, out)
			return
		}

		// notifications (no id): forward, answer 202 per the transport spec
		if len(req.ID) == 0 {
			// only MCP notifications/* forward id-less: an id-less tools/call
			// would otherwise reach upstream without passing the gate
			if !IsNotification(req.Method) {
				writeJSON(w, http.StatusBadRequest, Response{JSONRPC: "2.0", ID: json.RawMessage("null"),
					Error: &RPCError{Code: CodeInvalidRequest, Message: "id-less request: only notifications/* may omit an id"}})
				return
			}
			if _, _, err := u.RoundTrip(sessID, req); err != nil && e.Log != nil {
				e.Log.Printf("notification forward failed: %v", err)
			}
			w.WriteHeader(http.StatusAccepted)
			return
		}

		if req.Method == "tools/call" {
			var params ToolCallParams
			if err := json.Unmarshal(req.Params, &params); err != nil {
				writeJSON(w, http.StatusOK, Response{JSONRPC: "2.0", ID: req.ID,
					Error: &RPCError{Code: CodeInvalidParams, Message: "bad tools/call params"}})
				return
			}
			// forward exactly what the gate evaluated: canonical re-serialization
			// defeats duplicate-key parser differentials (round-4)
			canonical, merr := json.Marshal(params)
			if merr != nil {
				writeJSON(w, http.StatusOK, Response{JSONRPC: "2.0", ID: req.ID,
					Error: &RPCError{Code: CodeInternalError, Message: "bad tools/call params"}})
				return
			}
			req.Params = canonical
			result, forward, err := e.HandleToolCall(sess, params)
			if err != nil {
				writeJSON(w, http.StatusOK, Response{JSONRPC: "2.0", ID: req.ID,
					Error: &RPCError{Code: CodeInternalError, Message: err.Error()}})
				return
			}
			if !forward {
				writeJSON(w, http.StatusOK, DenyResponse(req.ID, result))
				return
			}
			resp, _, err := u.RoundTrip(sessID, req)
			if err != nil {
				writeJSON(w, http.StatusBadGateway, Response{JSONRPC: "2.0", ID: req.ID,
					Error: &RPCError{Code: CodeInternalError, Message: err.Error()}})
				return
			}
			e.IngestResult(sess, params, resp.Result)
			if resp.Error != nil {
				if eb, eberr := json.Marshal(resp.Error); eberr == nil {
					e.IngestUpstream(sess, eb)
				}
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}

		// passthrough
		resp, _, err := u.RoundTrip(sessID, req)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, Response{JSONRPC: "2.0", ID: req.ID,
				Error: &RPCError{Code: CodeInternalError, Message: err.Error()}})
			return
		}
		e.IngestResponse(sess, resp)
		writeJSON(w, http.StatusOK, resp)
	})
	return mux
}
