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
- COMPILED + TESTED since 2026-11-18 (first compile in gate round 1; the
  "written cold, reviewed by hand only" note above is historical — see the
  gate round logs below for the current CI state).

## Not done

- PR: open `funnel/referee` → `main` once the gate reaches APPROVED
  (repo main currently holds only the bootstrap README). HUMANS MERGE.
- Non-blocking reviewer items (tracked, not gate-blocking): HTTP session
  map aliasing/data races; bash-glob cap scoping is advisory not a
  boundary; dashboard approver identity is self-asserted; dashboard bearer
  compare is not constant-time; challenge excerpt 160-byte truncation can
  split a secret; challenge.Verified searches rules for challenge IDs that
  never occur; ProbeConsensus flag unused; AGENTS.md review-lane grammar.
- README license line says TBD — leave (repo stays private).
- Optional: push `feat/mvp-v0.1` to origin (funnel/referee is the PR
  branch; reconcile or drop feat/mvp-v0.1 at PR time).

## Next

1. Gate (`~/turbo-rig/scripts/review.sh --base main` on the VPS) — iterate
   REVISE rounds per the rig cap (Law 11: stop and present the fork after
   3+ rounds on the same theme).
2. On APPROVED: `gh pr create -R adventurewave-labs/referee --base main
   --head funnel/referee` with the PRD coverage body; DO NOT merge.
3. `handoff.sh done 2026-11-18-funnel-referee-r3.md --push --note "PR #N
   APPROVED, awaiting human merge"` to free the worker lane so
   funnel-tripwire-mvp and funnel-gauntlet-bootstrap dispatch.

## Gate round 7 log (2026-11-18)

- Round 6 (claude reviewer): REVISE — Verify refused fresh deployments
  (log shorter than one batch ⇒ heads file legitimately empty) and
  FUNNEL-STATE contradicted itself.
- Fix: Open writes a heads-meta line ({"heads_meta":{"batch":N}}) when it
  creates the heads file; verifyHeads honors it (first line only) so the
  empty-heads refusal now fires only when entries ≥ batch (a flush should
  have happened) or when the meta line itself was truncated away — the
  round-1 tamper bypass stays closed either way.
- TestFreshDeploymentVerifies added; `make demo` smoke: "[verify] receipt
  chain ok: 3 entries, 0 batch-head signatures verified" — the exact
  scenario from the round-6 finding, now green.
- FUNNEL-STATE Not done / Next rewritten to current truth.
- CI: green.

## Gate round 8 log (2026-11-18)

- Round 7 (claude reviewer): REVISE — heads_meta was unsigned (a forged
  batch size excused zero heads) and Verify never checked entries after
  the last kept head.
- Fix: the meta line is now SIGNED with the receipt ed25519 key
  (referee-heads-meta|batch=N); an invalid/unsigned meta refuses
  fail-closed, and Verify enforces Open's reopen tail rule (entries after
  the last signed head must be < batch).
- Regressions: TestForgedHeadsMetaRefused, TestUnsignedTailRefused,
  TestFreshDeploymentVerifies — all green. CI: green.
