# Funnel state — referee observe (feat/observe-r13)

## Done
- observe package: receipt-log analyzer (cost profile per tool: probe decisions, cap-gap counts), auto-narrowing suggestions (tighten candidates, unused-cap pruning), task-class attribution with complete-attribution guard (unknown/partial/empty mappings suppress unsupported conclusions), policy-hash binding (grants of a different policy never pruned on another's traffic), policy validation against known classes.
- CLI: referee observe --log --policy --task-class k=v (repeatable, validated).
- receipts: VerifyEntries in-memory TOCTOU fix; PolicyHash field (legacy-compat preimage).
- Policy.Hash() canonical digest; engine stamps receipts with it; serve wires it.
- CI green (race on, 15 packages).

## Not done
- GATE blocked by infrastructure: claude quota wall (>=75pct conserves) + codex family-rule refusal (no valid lane). 2 gate attempts blocked. Per the gate's own message: fix roster / wait quota / personal review.
- PR not opened (gate is absolute; no APPROVED verdict exists).

## Next (mp's fork)
1. When quota recovers: run gate (review.sh -C observe-worktree --base origin/main) → open PR feat/observe-r13 → main.
2. Or: personal review + merge directly (humans merge).
3. Roadmap after: multi-agent A2A (P2), policy verification (P2), community packs.
