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

- Round-9 gate fixes are committed but UNVERIFIED remotely (this update rides
  the fix commit; the next session verifies with `bash scripts/ci.sh`).
- Deferred (reviewer non-blocking, tracked): unbounded anon-N HTTP sessions,
  session-map aliasing on initialize (http.go), tuner Report counting
  judge-failure taints separately.
- PR not open yet: after the re-gate returns APPROVED,
  `gh pr create -R adventurewave-labs/referee --base main --head funnel/referee`.
  Humans merge; feat/mvp-v0.1 reconciles (delete) at merge time.

## Next

1. Gate (`~/turbo-rig/scripts/review.sh --base main` on the VPS) — iterate
   REVISE rounds per the rig cap (Law 11: stop and present the fork after
   3+ rounds on the same theme).
2. On APPROVED: `gh pr create -R adventurewave-labs/referee --base main
   --head funnel/referee` with the PRD coverage body; DO NOT merge.
3. `handoff.sh done 2026-11-18-funnel-referee-r3.md --push --note "PR #N
   APPROVED, awaiting human merge"` to free the worker lane so
   funnel-tripwire-mvp and funnel-gauntlet-bootstrap dispatch.

## FINAL STATE v2 (2026-11-19) — rounds 13-15 done, gate APPROVED, PR #4 open

- PRs #1/#2/#3 MERGED (mp). Round-12 findings fixed in rounds 13-15; **gate APPROVED (round 15)**; CI green at acc1cd8.
- PR #4 open: https://github.com/adventurewave-labs/referee/pull/4 (funnel/referee → main — the fixes; one click for mp).
- Design decision of record: high-labeled UNTRUSTED blocks fail the probe closed (judge is blind to withheld content); operator-intended secret reads are labeled trusted+high (PRD §5.1 canonical case) — exfil gates on conf, probe stays unblinded. Documented in label-semantics.md + threat-model.md.
- Residuals of record (threat-model.md): symlink/TOCTOU escapes past lexical path canonicalization; v1 receipt logs not readable by v2 (archive/migrate).

## Parked state (2026-11-18 ~19:30 CST) — superseded

- PR #1 open: https://github.com/adventurewave-labs/referee/pull/1 (funnel/referee → main, 🚫 not for merge — round-12 REVISE with codex's 10 findings listed in the PR body as the merge roadmap).
- Stacked PR #2: feat/probe-tuner-r4 → funnel/referee (tuner APPROVED on its own diff round 1; codex round-2 has two small findings open).
- History graft: 1294cbb joined the unrelated bootstrap main root (ours won README).
- Gate trail: rounds 1-8 plane worker (died 12:09 CST), 9-11 cockpit takeover (claude), 12 codex rotated in → 7×P1 (path traversal in cap scopes, judge-prompt confidentiality, probe cache trust boundary, expiry-during-probe forwarding, receipt delimiter ambiguity, upstream env inheritance, trailing-JSON verdict parse) + 3×P2.
- Next session: fix the round-12 list on this branch, re-gate (expect the codex lane), then rebase the tuner stack, re-gate #2's two small findings, and only then lift the 🚫.
- Branch wrinkle: tuner history lives on feat/probe-tuner-r4 (rebased; r2/r3 on origin are stale and safe to delete at merge time — created by this session).

## Cockpit takeover (2026-11-18 ~17:00 CST)

- Plane worker vmi3680747 died at 12:09 CST (last heartbeat); mp directed the
  cockpit session to continue. Round-9 (round 9 overall): REVISE — challenge
  payload leaked unredacted arg KEY names + undeclared tool names stored raw
  in receipts. Fixed in cccb1d6 with regressions; mrkdwn escaping + doc
  residuals folded in. Re-gate pending.

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
