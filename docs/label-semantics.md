# Referee — label semantics reference (§5.1, normative)

## The tag schema

Every content block entering the agent context through Referee carries:

| Field | Meaning |
|---|---|
| `block-id` | unique id of this ingested block (`b-0007`) |
| `source` | where it came from (`operator`, `user`, `tool:<name>`, `web`, `rag`, `file:<path>`) |
| `trust` | integrity label: `trusted` / `semi-trusted` / `untrusted` |
| `sensitivity` | confidentiality label: `normal` / `high` |
| `timestamp` | ingestion time |

**The two labels are never conflated.** A trusted-but-high block (an
operator-provided credential) is exfiltration-relevant but not
injection-relevant. An untrusted-but-normal block (a web page) is the
reverse. Every propagation step below moves the two labels independently.

## Sources and defaults

| Source | Default trust | Default sensitivity |
|---|---|---|
| operator prompt | trusted | normal |
| user message | semi-trusted (configurable) | normal |
| tool results | untrusted | normal |
| web / RAG content | untrusted | normal |
| file reads | by path policy | by path policy — secrets dirs → **high** |

Path policy (in the DSL `paths:` section) overrides the file-read defaults
per glob; the most specific pattern wins.

## Propagation — the containment matcher

When the gate evaluates a call, every argument value is reduced to a set of
**decoding variants**: identity, iterated URL-decoding, base64
(standard/unpadded/URL forms), hex, JSON string escapes, bare `\uXXXX`
escapes. Encoded secrets still match. Two bounded rounds catch
double encodings; the fan-out is capped at 64 variants.

Each variant is matched against every block in the session's shadow context:

- **Exact**: block text appears in a variant (block pasted into the
  argument), or a variant appears inside the block (argument quoted from the
  block) — both spans must be ≥ 8 characters, so tiny arguments cannot match
  the world.
- **Fuzzy**: any ≥ 12-character alphanumeric token of a block appears in the
  argument (lowercased) — reworded injections carrying identifiers still
  match.

Matching propagates **both labels independently**:

- any matched `untrusted` block → the argument is **integrity-tainted**;
- any matched `high` block → the argument is **confidentiality-high**.

Residual bypass (reworded/paraphrased or split secrets that defeat even
fuzzy+decoded matching) is a named limitation (threat-model §11.1) with a
regression test per normalization (`internal/labels/labels_test.go`).

## The influence probe (integrity axis only)

If containment found no taint, the tool's integrity verb is stricter than
`trust-any`, and untrusted blocks exist in the shadow context, a bounded LLM
judge answers a **set-based question**:

> could this argument have been constructed using ONLY the trusted blocks —
> i.e. without ANY of the untrusted blocks {B1…Bn} as a whole?

Asking about the *set* defeats repeated-injection redundancy: two copies of
an injected instruction cannot each hide behind the other, because the
question removes them all at once. Per-block attribution is evidence-only,
never decision-bearing.

Properties (all asserted by tests):

- **Schema-strict verdicts**: `{"verdict": "tainted"|"clean", "confidence": 0..1}`;
  anything else is a violation.
- **Fail-closed**: judge error, timeout, unparseable output → tainted.
- **Cache key** = `(untrusted-set-hash, argument-normalized-hash, sink-class)`;
  the *full* untrusted set is hashed, so a negative cached in an earlier
  context state cannot clear the same argument after new untrusted blocks
  arrive.
- **Consensus mode** (two judges, `probe_consensus: true`): disagreement
  collapses to tainted.
- The gate **blocks synchronously** on the verdict — a stated property
  (§5.1), budgeted at < 1.5 s p95 with cache; containment-only path stays
  under 5 ms (asserted in CI).

"No taint detected" means containment + (if applicable) the set-probe
cleared it. Receipts phrase it as **not detected**, never as *clean*.

## Argument classification (confidentiality)

When propagation was silent, the argument class decides sensitivity: a
rule-based classifier over credential shapes (AWS/GitHub/Slack keys, PEM
blocks, bearer tokens, `password=` patterns) plus an entropy heuristic for
random-looking runs. Defaults bias **high**: a false "high" costs one
challenge; a false "normal" can cost a secret.
