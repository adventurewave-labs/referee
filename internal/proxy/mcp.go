// Package proxy implements the MCP middleware proxy (PRD §7): the agent's
// tool config points at Referee; Referee intercepts tools/call, runs the
// two-axis gate, captures tool results into the per-session shadow context,
// and forwards approved calls to the real MCP server. Transports: stdio and
// streamable-HTTP (JSON mode).
package proxy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Request is a JSON-RPC 2.0 request/notification.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("rpc %d: %s", e.Code, e.Message) }

// Standard JSON-RPC codes plus Referee's gate-denied code.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
	// CodeGateDenied is Referee's own: the two-axis gate denied the call.
	CodeGateDenied = -32050
)

// ToolCallParams is the MCP tools/call request shape.
type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// ContentBlock is one MCP content item; v1 handles text blocks.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// ToolCallResult is the MCP tools/call result shape.
type ToolCallResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

// DenyResult builds the MCP error result the agent sees when the gate
// denies a call. The upstream tool never runs.
func DenyResult(decision string, rule, reason string) ToolCallResult {
	return ToolCallResult{
		Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf(
			"referee: denied by policy gate (decision=%s rule=%s) — %s", decision, rule, reason)}},
		IsError: true,
	}
}

// IsNotification reports whether method is an MCP notification — the only
// messages allowed to omit an id and bypass the request/response path.
func IsNotification(method string) bool {
	return strings.HasPrefix(method, "notifications/")
}

// DenyResponse wraps a gate denial as a JSON-RPC error carrying Referee's
// own code, so agents and clients can tell a policy denial apart from a tool
// failure. The denial text (no argument values) is the message.
func DenyResponse(id json.RawMessage, r ToolCallResult) Response {
	msg := "referee: denied by policy gate"
	if len(r.Content) > 0 {
		msg = r.Content[0].Text
	}
	return Response{JSONRPC: "2.0", ID: id, Error: &RPCError{Code: CodeGateDenied, Message: msg}}
}

// TextFromResult concatenates the text content blocks of a tools/call
// result for shadow-context ingestion.
func TextFromResult(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var r ToolCallResult
	if err := json.Unmarshal(raw, &r); err != nil {
		return ""
	}
	var sb strings.Builder
	for _, c := range r.Content {
		if c.Type == "text" || c.Type == "" {
			sb.WriteString(c.Text)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}
