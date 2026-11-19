# Referee — policy cookbook

The DSL is YAML, capability-style, deliberately **not** Turing-complete.
The compiler validates at load (`referee policy check`) and every deny /
challenge / approve decision cites the clause that fired, so a policy is
debuggable from receipts alone. Dry-run before you swap a live policy:
`referee policy diff --policy current.yaml --against candidate.yaml`.

## The mental model

1. **Every tool call needs a capability token** (§5.3 step 1). No cap →
   deny, unless the tool opted into `cap_gap_challenge` AND has approvers.
2. **Each axis has a verb per tool**:
   - integrity: `trust-any` → `challenge-if-tainted` → `require-trusted`
   - confidentiality: `sensitivity-any` → `challenge-if-high` → `require-normal`
3. **Clean calls auto-approve.** A call passing every gated axis never
   reaches a human — `challenge-if-*` means "challenge only IF", and clean
   calls pass the condition by definition.
4. **Deny beats challenge beats approve.** Nothing goes to a human that
   policy would deny anyway.
5. **Default posture is deny**: undeclared tools have no caps, and
   cap-gap-challenge is opt-in.

## Choosing verbs (worked examples)

**Exec (bash, exec):** `require-trusted` + `require-normal`. The injection
prize — there is no human path for tainted exec: it is denied outright.
Scope caps tightly: `pattern: "make *"` on `scope_arg: command`.

**Reads (read_file, web_fetch, search):** `trust-any` +
`sensitivity-any` with `emits:` set (`file-read` + `emit_path_arg: path` for
files, `web`/`rag` for fetches). Reads are *sources*: whatever they return
is untrusted content, which is the point — gate the sinks, feed the shadow
context.

**Email / messaging:** `challenge-if-tainted` + `challenge-if-high` with a
non-empty `approvers` allowlist. Tainted *or* high goes to a human with a
redacted payload; clean routine mail flows through.

**High-side infra (deploy registries, secrets managers):** the tool needs a
`[sensitivity: high]` cap in the task class — a normal cap NEVER authorizes
a high call (§5.2). Verb stays `challenge-if-high` if you want untrusted
influence near it challenged; `require-normal` if the sink must never move
secrets at all.

**Known-credential tools** (a secrets manager the operator intends the agent
to use): `sensitivity-any` — the operator accepts the confidentiality risk
structurally instead of challenging every legitimate credential use; the
receipt still records the labels.

## Task classes and caps

```yaml
tasks:
  - class: deploy-preview
    ttl: 4h                # absolute wall-clock; clamped DOWN to ttl_ceiling
    caps:
      - tool: bash
        scope_arg: command
        pattern: "make *"
        sensitivity: normal
      - tool: http_post
        pattern: "*"
        sensitivity: high
```

At task start the harness sends `referee/task_start {task_id, task_class,
caps?, control_token}`. The control RPCs share the agent's stream, so the
privileged ones (`task_start`, `user_block` — they mint caps or add trusted
content) require `control_token` to equal `$REF_CONTROL_TOKEN` on the
referee process; with no token configured they are refused and tasks start
only via `serve --task-id/--task-class`. `task_end` and `status` need no
token (they only shrink authority or read state). Requested cap names **narrow, never widen**: the minted caps are
the policy's own declarations for that class, restricted to the requested
subset. Two hard death conditions, whichever comes first: `referee/task_end`
revokes instantly (no grace window) and the absolute TTL kills the token
even if no end signal ever arrives.

## Scope patterns

Globs with unix semantics: `**` crosses `/`, `*` does not, `?` is one
character. With `scope_arg` set, the pattern matches that argument's value
(e.g. `path`); without it, the cap covers the whole tool. Cap patterns and
path-policy patterns share the same matcher.

## Approvers and challenges

`approvers` is the per-tool allowlist of authenticated approver ids (Slack
user ids in slack mode; names in local mode). Challenges are:

- **redacted by construction** — argument shapes with secrets masked, HMAC
  block refs, hostile excerpts clearly marked (never high-sensitivity text);
- **single-use** — each pending challenge resolves once;
- **authorized** — clicks from non-allowlisted users are rejected and logged;
- **timeout-default-deny** — `--challenge-timeout` (default 5m) with nobody
  deciding means deny, never approve.

Local mode (dev/dogfood): approve from the dashboard or
`referee approve --challenge-id <id> --allow`.

## Probe tuning knobs

- `probe_timeout` (defaults): total budget per probe; timeout = tainted.
- Two `judges:` entries + `probe_consensus: true` on a tool = consensus
  mode: both must say clean; disagreement = tainted. Reserve for
  max-severity gates (exec, secrets sinks) — it doubles probe spend.
- The cache is keyed `(untrusted-set-hash, arg-hash, sink-class)`; you never
  tune it, but `sink_class` on a tool controls cache granularity — leave it
  unset (= tool name) unless several tools share one semantic sink.

## Debugging a policy

1. `referee policy check --policy p.yaml` — compile errors first.
2. Run the workload, then `referee why --log ... --task <task>` — every
   decision cites its rule (`cap:missing`, `integrity:require-trusted+tainted`,
   `conf:challenge-if-high+high`, `auto:clean(...)`).
3. `referee policy diff` before swapping — the gate's semantics change
   exactly along the reported lines.
