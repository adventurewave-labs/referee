# Funnel state — referee (adventurewave-labs/referee)

Branch: `funnel/referee` (worktree at `~/funnel/referee`; same commit as
`feat/mvp-v0.1` in mp's local clone). Remote `origin` =
https://github.com/adventurewave-labs/referee (PRIVATE repo, already created).
Push with `gh` auth or the https remote; agents never touch main — PR only.

## Done

- Full Go scaffold written (module `github.com/adventurewave-labs/referee`,
  single direct dep: gopkg.in/yaml.v3), implementing the referee PRD v0.4
  normative core (§5.1–§5.4, §7, §8 regressions):
  - `internal/labels` — tag schema, source registry + path policy, decoding
    normalizations (url/base64 std+raw+url/hex/json/unicode, bounded fan-out),
    containment matcher (exact bidirectional ≥8-char spans + ≥12-char tokens),
    rule-based classifier (credential shapes + entropy), shared glob matcher.
  - `internal/policy` — YAML DSL, compiler/validation, manifest narrowing
    (narrow-never-widen), dry-run diff (`policy.Diff`).
  - `internal/caps` — sensitivity-bearing task tokens; absolute TTL clamped
    to ceiling; immediate task-end revocation; TTL-alone death.
  - `internal/probe` — set-based influence judge, schema-strict parse,
    cache keyed `(untrusted-set-hash, arg-hash, sink-class)`, fail-closed,
    consensus mode; OpenAI-compatible + Anthropic HTTP judges + MockJudge.
  - `internal/gate` — normative §5.3 algorithm (capability → integrity →
    confidentiality → clean-auto-approve → default deny; deny > challenge >
    approve merge).
  - `internal/receipts` — hash-chained JSONL, keyed args-HMAC, ed25519 batch
    heads, tamper-detecting verify, search (`referee why`).
  - `internal/challenge` — redacted-by-construction payloads, allowlist +
    single-use resolution, timeout-default-deny, Slack notifier with signed
    interactive endpoint (`v0:` HMAC, ±5 min), local approver.
  - `internal/proxy` — MCP middleware: JSON-RPC types, per-session shadow
    context, engine pipeline, stdio transport (notification passthrough,
    referee/* control RPCs: task_start/task_end/user_block/status),
    streamable-HTTP JSON mode (`HTTPHandler` + `RunHTTP`).
  - `internal/dashboard` — in-binary operator surface + local challenge
    approver (Bearer token), `/api/*`.
  - `cmd/referee` — serve (stdio|http), verify, why, policy check|diff,
    demo, approve.
  - `internal/demo` — self-contained §8 scenario (poisoned page → encoded
    exfil → redacted challenge timeout-deny; clean run auto-approves;
    task-end kills token; verify at the end).
  - Tests in every package incl. §8 regressions (raw/base64/url/hex secret →
    conf-high), double-injection set-probe, gate §5.3 matrix, tamper
    detection, Slack signature verification, stdio+HTTP e2e,
    `TestContainmentLatencyBudget` (<5ms) + bench.
- Docs: README, docs/threat-model.md, docs/label-semantics.md,
  docs/policy-cookbook.md; examples/policy-coding-agent.yaml; CI workflow;
  scripts/ci.sh; Makefile; repo AGENTS.md (gate anchor).
- 2026-11-18 (Mac-side unblock): the bare `referee` line in `.gitignore`
  was swallowing `cmd/referee/` — the CLI source (main/cmds/serve.go)
  never entered commit be83ff2, so the first two shipped bundles had NO
  CLI to compile (plane worker r2 came back BLOCKED for exactly this).
  Fixed: line is now root-anchored `/referee` (binary only), `cmd/referee`
  copied from the parent clone and committed on `funnel/referee`, branch
  pushed to origin. Same `.gitignore` fix applied (uncommitted) to the
  parent clone's working tree at
  `~/Downloads/turbo-rig/projects/referee`.
- NEVER compiled or tested yet — no Go toolchain on the Mac cockpit; the
  whole tree was written cold and reviewed by hand only. First build is the
  next session's job.

## Not done

- `bash scripts/ci.sh` (bootstraps Go 1.22.10 into /tmp, then mod tidy +
  vet + build + test + bench) — expect compile fixes; iterate until green.
- `go.sum` generation (go mod tidy does it; copy into repo and commit).
- Push `feat/mvp-v0.1` to origin (`funnel/referee` already pushed; the PR
  branch is funnel/referee — reconcile or drop feat/mvp-v0.1 at PR time).
- Rig gate: `review.sh` per constitution (builder ≠ reviewer, fail-closed)
  before the PR.
- Open PR on GitHub: `feat/mvp-v0.1` → `main` (repo main currently holds
  only the bootstrap README). HUMANS MERGE — agent must not merge.
- README license line says TBD — leave (repo stays private).

## Next

1. `cd ~/funnel/referee && bash scripts/ci.sh` — fix compile/test failures
   until green (`go vet` first; watch for unused imports, the usual).
   Known risk spots: engine.go wiring, stdio notification path, glob
   backtracking, receipts hash round-trip through JSON time.
2. Commit fixes on this branch (funnel/referee). Push:
   `git push -u origin funnel/referee`.
3. Run the gate (`~/turbo-rig/scripts/review.sh --base main` on the VPS per
   rig constitution; log the verdict). Fix REVISE rounds if any (cap: 3
   rounds on the same theme, then park and report).
4. `gh pr create -R adventurewave-labs/referee --base main --head
   funnel/referee --title "referee v0.1 — IFC middleware scaffold (PRD §5.1–§5.4)" `
   with a body listing PRD sections covered + §8 regressions + known
   limitations. Do NOT merge.
5. Update this file as you go; leave `remote-out/` uncommitted (gitignored).

## Gate round 2 log (2026-11-18)

- Round 1 (codex reviewer): REVISE — 5 findings (control-RPC authority
  minting; per-value gate matching; empty-heads receipt bypass; challenge
  payload disclosure; receipt-write failures not fail-closed).
- Fixes: control-token auth for task_start/user_block (REF_CONTROL_TOKEN,
  constant-time compare, disabled when unset) + HTTP control result shape;
  receipts fail-closed on append error; per-argument raw-value matching in
  the gate (JSON map escaping/wrapping defeated reverse containment);
  empty/truncated heads file refuses verification; challenge payloads never
  emit raw argument text (shape-only) and secret-looking hostile excerpts
  are withheld (HMAC ref instead).
- Builder handoff: claude worker did round-1 compile+gate then was stopped
  mid-round-2 (roster: builders are GLM); GLM completed the remaining
  findings #2/#3/#4 + tests over SSH on the same lane. Reviewer stays codex.
- CI: go 1.22 vet+build+test+bench GREEN (containment 36.8µs/op, budget 5ms).
