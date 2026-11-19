# Referee — threat model

Scope: the MCP boundary between ONE agent and its tools (single-agent
topologies in v1; A2A is P2). Referee is a **choke point**: compromise of
the proxy equals compromise of the boundary it guards. Everything below is
written to be re-attacked by reviewers.

## Assets

- The tool boundary itself (exec, fs, network sinks reachable by the agent).
- High-sensitivity content: credentials in secrets paths, operator tokens.
- The decision log (integrity of the audit trail).

## Trust boundaries

1. **Agent context** — hostile by construction: tool results, web pages, RAG
   chunks, repo files are all attacker-influenceable (indirect prompt
   injection). Only `operator` blocks are trusted; `user` blocks are
   semi-trusted by default and configurable.
2. **Upstream MCP servers** — inside the boundary but untrusted for labeling:
   their outputs are `tool-result` (untrusted) unless policy says otherwise.
3. **Human approvers** — authenticated AND authorized: Slack buttons are
   signature-verified (±5 min replay window) and the Slack user id is checked
   against the per-tool allowlist at approval time. Non-allowlisted clicks
   are rejected and visible in the dashboard.
4. **The influence probe judge** — an untrusted oracle: schema-strict output,
   fail-closed on error/timeout/parse, consensus (disagreement = tainted)
   for max-severity gates. The prompt forbids following in-block
   instructions, and the set-based question is designed so injected text
   cannot talk its way to a "clean".

## Attack surface and mitigations

| Attack | Mitigation |
|---|---|
| Indirect prompt injection steers a tool call | integrity axis: containment taint, else set-probe; `require-trusted` denies with no human path |
| Encoded exfil (base64/url/hex secrets in args) | decoding normalizations before containment; per-normalization §8 regressions |
| Repeated injection (two copies hide behind each other) | set-based probe question removes the whole untrusted set at once |
| Cache poisoning across context states | cache key includes the full untrusted-set hash — a negative cached earlier cannot clear after new untrusted blocks arrive |
| Normal cap used to move a secret | sensitivity coverage is part of the cap: high calls need high caps (§5.2) |
| Token reuse after task end | immediate revocation on task-end + absolute wall-clock TTL; no grace window; TTL alone kills tokens the harness never ends |
| Log tampering | hash chain + signed batch heads; tampered logs refuse to open; `referee verify` catches any flip |
| Log exfil reveals low-entropy args | args stored as keyed HMAC only; raw args never retained in v1 |
| Secret leaks via Slack challenge | redaction by construction: masked shapes, HMAC block refs, hostile excerpts of non-sensitive untrusted blocks only; full detail stays in the authenticated dashboard |
| Replay of Slack approvals | signed requests, ±5 min freshness, single-use consume, per-tool allowlist |
| Challenge infra down | fail closed: dispatch failure = deny (never approve) |
| Proxy compromise | minimal parser surface (strict JSON-RPC), no eval, memory-safe Go, fuzz targets on decoders; receipts key + signing seed are 0600 files |
| DoS the probe | containment path has no LLM dependency; probe cached per (set-hash, arg-hash, sink-class); per-process timeout budget |

## Named residual risks (honest scope, PRD §11)

1. **Transformed secrets**: paraphrased, split, or non-standard encodings
   that defeat decoded+fuzzy matching evade label propagation. The
   confidentiality set-probe does not exist in v1 (integrity-only probe per
   PRD). The classifier's entropy heuristic is a backstop, not a guarantee.
2. **Classifier miss**: a high-sensitivity argument the rule-based classifier
   marks normal gets no confidentiality gate — content-label propagation
   catches *copied* secrets; novel secrets that never touched a labeled
   block rely on the classifier. Defaults bias high.
3. **Missing task-end signal**: explicit-only v1 boundaries; a harness that
   never signals leaves caps alive until TTL. Visible in the dashboard.
4. **Probe quality**: false challenges erode trust; misses erode value.
   Conservative defaults ship; the paired-replay tuning harness ships with
   `referee tune` (methodology per arXiv:2610.05840).
5. **Unsigned receipt tail**: entries after the last signed batch head (up to
   one batch, 99 at the default size) are protected by the unkeyed hash chain
   only — someone who rewrites them AND recomputes hashes passes `referee
   verify`. Signed heads bound the window; they do not close it. Batch size 1
   signs every entry at throughput cost.
6. **The receipt public key is not a trust anchor**: `referee-pubkey.hex`
   (0644, working directory) sits next to the log it verifies — an attacker
   who can rewrite the log and heads can also swap the key. Anchor trust by
   keeping the public key elsewhere (keychain, offline copy, CI secret).

## What Referee does NOT protect

Model weights, the prompt template itself, agent-framework internals, or
anything upstream of the tool boundary (the agent's own reasoning is out of
scope — that is the label model's premise, not a bug). Multi-agent flows are
P2.
