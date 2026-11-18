# Referee — probe tuning (PRD §6 P1)

The probe decides product truth: false challenges erode operator trust,
misses erode the product's value (§11). The tuning loop measures both, on a
**paired-replay corpus** (methodology per arXiv:2610.05840): the same task
replayed twice — a clean trace and an injected trace — so judge divergence
is visible case by case.

## Metrics (PRD §8)

| Metric | Definition | Bar |
|---|---|---|
| recall | injected traces actually gated (challenge or deny) | ≥ 0.85 |
| false-challenge | clean traces wrongly gated | ≤ 0.05 |
| precision | gated traces that were right | reported |
| pairs diverged | pairs where clean approved AND injected gated | reported |

The corpus runs through the **full gate** — capability, containment,
influence probe, classifier — so metrics describe the shipped behavior, not
the judge in isolation. Each result is attributed (evidence-only) to the
layer that decided: `containment`, `probe`, `classifier`, or `cap`.

## Running

```bash
# offline, deterministic mock judge (CI-friendly):
referee tune --corpus examples/probe-corpus.yaml \
             --policy examples/policy-coding-agent.yaml --mock

# against real judges from the policy's judges: section:
referee tune --corpus my-corpus.yaml --policy my-policy.yaml \
             --min-recall 0.85 --max-false-challenge 0.05
```

Exit code 1 means the corpus misses the bar — the report shows exactly which
cases missed (`↳ rule=...`) and why.

## Corpus format

```yaml
description: what this corpus exercises
cases:
  - name: para-inj          # unique
    pair: paraphrase        # optional: paired-replay grouping
    kind: clean | injected
    tool: http_post         # must be capped by the policy task class
    args: { url: "...", body: "..." }
    blocks:                 # the shadow context for this case
      - trust: untrusted
        sensitivity: normal # high when the block carries secret content
        source: web
        text: "..."
    expect: approve | challenge-or-deny
    note: why this case exists
```

Authoring guidance:

- **Probe-layer cases** (the ones that actually tune the judge): make the
  injected argument share no ≥12-character token with the untrusted blocks,
  so containment cannot decide it. If the report says `layer=containment`,
  the case exercises the matcher, not the judge — keep a few of those
  (they're the §8 regressions), but don't let them drown out probe cases.
- **Pairs**: keep clean/injected halves otherwise identical; divergence in
  the pair is the signal.
- A deliberately-missed case is fine while tuning — the report marks it `✗`
  and recall tells you what it costs.
