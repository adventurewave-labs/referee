# AGENTS.md — referee (adventurewave-labs)

Defensive security product: information-flow control middleware between LLM
agents and their MCP tools (PRD: `docs/prd-referee.md` in the PRD repo;
spec sections §5.1–§5.4 are normative). Sessions in this repo follow the rig
constitution (`~/rig/AGENTS.md`). Repo invariants the review gate anchors on:

## Invariants (gate anchors — violations are automatic REVISE)

- Secrets never enter git, argv, or logs. Judge API keys, Slack tokens, and
  the receipt keys travel via env names (`REF_*`) or 0600 key files only.
- Receipts and challenge payloads are redacted by construction: raw tool
  arguments never appear in the receipt log (keyed HMAC only) or in challenge
  notifications (masked shapes only). A regression that leaks a secret-shaped
  value into either surface fails review.
- Fail closed is the law of the gate: probe error/timeout/missing judge =
  tainted; challenge dispatch failure = deny; tampered receipt log refuses to
  open. Any new code path that fails open on ambiguity is a REVISE.
- The two labels (trust / sensitivity) propagate independently and are never
  conflated (PRD §5.1).
- `referee verify` must keep catching tampering: any change to the chain
  format needs a round-trip test that flips a byte and expects failure.

## Build/test (remote plane per rig law; `scripts/ci.sh` bootstraps Go)

- `bash scripts/ci.sh` — tidy + vet + build + test + bench (single entry).
- `make fuzz` — native fuzz targets (seed corpus also runs in `go test`).
- The containment-path budget (<5ms/call) is asserted in
  `internal/gate/gate_test.go:TestContainmentLatencyBudget` — keep it.

## Review lane

- Deterministic checks only; verdict line protocol per rig Law 2.

## Conventions

- Go stdlib first; the only direct dependency is `gopkg.in/yaml.v3`.
- Normative PRD language stays in code comments where the behavior lands
  (search for "§5.1", "§5.2", "§5.3", "§5.4", "§8").
