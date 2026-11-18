# Referee

**Taint-tracking & task-scoped authorization middleware for agents.**
A middleware proxy between LLM agents and their tools: every untrusted input
entering the agent context is tainted with provenance labels; each tool call
is gated along two independent axes — *injection* (did untrusted content
influence the call?) and *exfiltration* (does the call move high-sensitivity
content?) — and auto-approved only when clean on every axis the policy
gates. Actions the policy can't clear get per-task, expiring capability
tokens and redacted human challenges — never ambient authority.

Design: PRD "Referee" v0.4 (adventurewave-labs/agentic-cybersecurity-development-prds,
`docs/prd/referee.md`) — the IFC design follows CaMeL (arXiv:2503.18826)
with set-based influence probes, task-scoped authorization
(arXiv:2610.05840), and the operationalization gaps from arXiv:2505.22852.

## How it works

```
agent ──MCP──► referee (this proxy) ──MCP──► real tools
                 │
                 ├─ label engine: provenance tags per content block
                 ├─ containment matcher: exact + fuzzy + decoded matching
                 ├─ influence probe: set-based LLM judge (fail-closed)
                 ├─ capability tokens: task-scoped, sensitivity-bearing, TTL + task-end
                 ├─ two-axis gate: capability → integrity → confidentiality → clean-auto-approve
                 ├─ receipts: hash-chained JSONL, HMAC'd args, signed batch heads
                 └─ challenges: redacted Slack buttons / local approver, timeout = deny
```

The gate is deterministic where argument containment holds
(< 5 ms/call, asserted in CI); the influence probe runs only on
integrity-gated calls without containment matches, and the gate *blocks
synchronously* on its verdict — that blocking is a stated property, not a
bug.

## Quick start

```bash
# self-contained end-to-end demo (poisoned page → exfil attempt →
# redacted challenge; clean run → auto-approve) — no network needed
go run ./cmd/referee demo

# point a coding agent at Referee instead of the raw MCP server:
referee serve --policy examples/policy-coding-agent.yaml \
  --mode stdio --upstream-cmd "uvx mcp-server-fetch"
```

The agent's tool config points at Referee; no framework changes.

## Verify receipts

```bash
referee verify --log referee-receipts.jsonl --heads referee-heads.jsonl --pubkey <pub>
referee why --log referee-receipts.jsonl --decision deny --task deploy-preview-42
```

Every gate decision emits a receipt: which blocks influenced the call and
which policy clause fired — args are keyed-HMAC'd, never stored raw.

## Package map

| Package | PRD section | What it does |
|---|---|---|
| `internal/labels` | §5.1 | tag schema, source registry + path policy, decoding normalizations, containment matcher, rule-based classifier |
| `internal/policy` | §5.2/§5.3 | YAML DSL, compiler, dry-run diff, manifest narrowing |
| `internal/caps` | §5.2 | sensitivity-bearing task tokens; TTL + immediate task-end revocation |
| `internal/probe` | §5.1 | set-based influence probe; cache `(set-hash, arg-hash, sink-class)`; fail-closed; consensus |
| `internal/gate` | §5.3 | the normative two-axis decision algorithm |
| `internal/receipts` | §5.4 | hash-chained log, args HMAC, ed25519 batch heads, verify |
| `internal/challenge` | §5.4/§9 | redacted challenges, allowlist + single-use approvers, Slack signatures, timeout-default-deny |
| `internal/proxy` | §7 | MCP middleware (stdio + streamable-HTTP JSON mode), per-session shadow context |
| `internal/dashboard` | §6 | in-binary operator surface (sessions, decisions, verify, local approver) |
| `cmd/referee` | — | CLI: serve / verify / why / policy / demo / approve |

## Status

v0.1 (first working scaffold) — P0 scope minus the probe-tuning loop (P1)
and SIEM export (P1). Known limitations are documented honestly in
[docs/threat-model.md](docs/threat-model.md) (§11 residual risks: transformed
secrets that defeat all normalizations, classifier misses, missing task-end
signals bounded by TTL).

**Not shipped yet:** SSE streaming upstream (JSON mode only), idle-heuristic
task-end (experimental opt-in per PRD; explicit-only v1 shipped), encrypted
evidence escrow (off by default per PRD), framework presets (P1).

## Security posture

Referee is a choke point: compromise of the proxy = compromise of the
boundary. Minimal parser surface (strict JSON-RPC schema), memory-safe Go,
fuzz targets on the decoders (`make fuzz`), no eval. Judge prompts treat
block content as hostile data. Secrets never enter git, argv, or logs.

## Development

```bash
bash scripts/ci.sh   # vet + build + test + bench (bootstraps Go on remote boxes)
make fuzz            # decoder fuzzing
make demo            # end-to-end scenario
```

CI asserts the §8 regression suite (per-normalization secret encodings,
double-injection set-probe) and the containment-path latency budget.

License: TBD before open-sourcing (currently private to adventurewave-labs).
