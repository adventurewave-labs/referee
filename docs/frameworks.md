# Referee — framework presets (PRD §6 P1, SDK-less)

Referee is an MCP middleware proxy: any agent framework that speaks MCP
points its tool config at Referee instead of the raw server — no SDK, no
code changes. These are the shipped presets; each is a config snippet, not
an integration.

## Claude Code (and Claude-Code-style MCP config)

`.mcp.json` / `claude mcp add` — wrap one upstream server:

```json
{
  "mcpServers": {
    "referee": {
      "command": "referee",
      "args": [
        "serve", "--mode", "stdio",
        "--policy", "/etc/referee/policy-coding-agent.yaml",
        "--upstream-cmd", "uvx mcp-server-fetch",
        "--task-class", "research",
        "--log", "/var/lib/referee/receipts.jsonl"
      ]
    }
  }
}
```

Task boundaries: Claude Code sessions are one task — the operator's harness
sends `referee/task_start` when the session begins (via a hook or wrapper)
or `--task-id/--task-class` pins it for the process lifetime. The
`referee/task_end` signal revokes caps instantly; process exit revokes too
(`serve` ends the task on shutdown).

## Generic MCP clients (stdio)

The same shape as above: wherever your client takes a *command* for an MCP
server, give it `referee serve --mode stdio --upstream-cmd "<real server>"`.
Everything the client sends is intercepted at `tools/call`; everything else
passes through verbatim.

## Generic MCP clients (streamable-HTTP)

Point the client at Referee's middleware endpoint instead of the server's:

```yaml
# client MCP config (HTTP mode)
mcp_servers:
  - url: http://127.0.0.1:8199/mcp
```

```bash
referee serve --mode http \
  --policy /etc/referee/policy.yaml \
  --upstream-url http://127.0.0.1:9000/mcp \
  --listen 127.0.0.1:8199 \
  --dashboard 127.0.0.1:8200 \
  --siem-endpoint https://siem.internal:4318
```

The client's `Mcp-Session-Id` header keys the per-session shadow context.
Referee v1 speaks the JSON mode of streamable-HTTP (one JSON-RPC message per
POST; SSE upstream streaming is a documented v1 limitation).

## OpenAI/Anthropic tool-loop agents (no MCP client)

Agents that call LLM APIs directly with their own tool loop connect through
the MCP boundary by running their tools as MCP servers and letting Referee
gate the loop's tool-call step:

1. Run the agent's tools behind an MCP server (or a thin adapter that maps
   the agent's tool schema to MCP).
2. Put Referee between the loop and that server (stdio preset above).
3. The loop's tool-call step issues `tools/call` through Referee — the gate,
   receipts, and challenges apply unchanged.

The loop is the harness: it must send `referee/task_start` when work begins
and `referee/task_end` when it finishes (TTL is the backstop).

## Env + secrets (all presets)

Judge keys and challenge credentials travel via env (`REF_JUDGE_API_KEY`,
`REF_SLACK_BOT_TOKEN`, `REF_RECEIPT_HMAC`) — never argv, never git. Upstream
MCP servers launched by Referee inherit only an allowlisted environment
(`PATH`/`HOME`/`USER`/`LOGNAME`/`TMPDIR`/`LANG`/`TERM`/`SHELL`) — Referee's
own secrets never cross to them.
