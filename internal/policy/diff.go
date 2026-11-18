package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/adventurewave-labs/referee/internal/labels"
)

// Diff renders the dry-run diff between two policies (PRD P0: compiler with
// dry-run diff mode). It reports what changes for the gate, not YAML syntax —
// operators use it before swapping a live policy.
func Diff(a, b *Policy) string {
	var sb strings.Builder
	toolNames := map[string]bool{}
	for n := range a.Tools {
		toolNames[n] = true
	}
	for n := range b.Tools {
		toolNames[n] = true
	}
	names := make([]string, 0, len(toolNames))
	for n := range toolNames {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		ta, oka := a.Tools[n]
		tb, okb := b.Tools[n]
		switch {
		case oka && !okb:
			fmt.Fprintf(&sb, "tool %s: REMOVED (was integrity=%s conf=%s)\n", n, ta.Integrity, ta.Confidentiality)
		case !oka && okb:
			fmt.Fprintf(&sb, "tool %s: ADDED (integrity=%s conf=%s approvers=%d)\n", n, tb.Integrity, tb.Confidentiality, len(tb.Approvers))
		case oka && okb:
			if ta.Integrity != tb.Integrity {
				fmt.Fprintf(&sb, "tool %s: integrity %s -> %s\n", n, ta.Integrity, tb.Integrity)
			}
			if ta.Confidentiality != tb.Confidentiality {
				fmt.Fprintf(&sb, "tool %s: confidentiality %s -> %s\n", n, ta.Confidentiality, tb.Confidentiality)
			}
			if !equalStrings(ta.Approvers, tb.Approvers) {
				fmt.Fprintf(&sb, "tool %s: approvers %v -> %v\n", n, ta.Approvers, tb.Approvers)
			}
			if ta.CapGapChallenge != tb.CapGapChallenge {
				fmt.Fprintf(&sb, "tool %s: cap_gap_challenge %t -> %t\n", n, ta.CapGapChallenge, tb.CapGapChallenge)
			}
			if ta.ProbeConsensus != tb.ProbeConsensus {
				fmt.Fprintf(&sb, "tool %s: probe_consensus %t -> %t\n", n, ta.ProbeConsensus, tb.ProbeConsensus)
			}
		}
	}

	classNames := map[string]bool{}
	for n := range a.Tasks {
		classNames[n] = true
	}
	for n := range b.Tasks {
		classNames[n] = true
	}
	for _, n := range sortedKeys(classNames) {
		ta, oka := a.Tasks[n]
		tb, okb := b.Tasks[n]
		switch {
		case oka && !okb:
			fmt.Fprintf(&sb, "task %s: REMOVED (had %d caps)\n", n, len(ta.Caps))
		case !oka && okb:
			fmt.Fprintf(&sb, "task %s: ADDED (ttl=%s caps=%d)\n", n, tb.TTL.D(), len(tb.Caps))
		default:
			if ta.TTL != tb.TTL {
				fmt.Fprintf(&sb, "task %s: ttl %s -> %s\n", n, ta.TTL.D(), tb.TTL.D())
			}
			if !equalCaps(ta.Caps, tb.Caps) {
				fmt.Fprintf(&sb, "task %s: caps changed (%d -> %d)\n", n, len(ta.Caps), len(tb.Caps))
				for _, d := range capDiff(ta.Caps, tb.Caps) {
					fmt.Fprintf(&sb, "  cap: %s\n", d)
				}
			}
		}
	}

	if a.Defaults.TTLCeiling != b.Defaults.TTLCeiling {
		fmt.Fprintf(&sb, "defaults: ttl_ceiling %s -> %s\n", a.Defaults.TTLCeiling.D(), b.Defaults.TTLCeiling.D())
	}
	if len(a.Registry.PathRules) != len(b.Registry.PathRules) || !equalPaths(a.Registry.PathRules, b.Registry.PathRules) {
		fmt.Fprintf(&sb, "paths: %d rules -> %d rules\n", len(a.Registry.PathRules), len(b.Registry.PathRules))
	}
	if len(a.Judges) != len(b.Judges) {
		fmt.Fprintf(&sb, "judges: %d -> %d\n", len(a.Judges), len(b.Judges))
	}

	if sb.Len() == 0 {
		return "no semantic changes"
	}
	return strings.TrimRight(sb.String(), "\n")
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func equalStrings(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	xs, ys := append([]string(nil), x...), append([]string(nil), y...)
	sort.Strings(xs)
	sort.Strings(ys)
	for i := range xs {
		if xs[i] != ys[i] {
			return false
		}
	}
	return true
}

func equalCaps(x, y []CapDecl) bool {
	if len(x) != len(y) {
		return false
	}
	xk, yk := capKeySet(x), capKeySet(y)
	if len(xk) != len(yk) {
		return false
	}
	for k := range xk {
		if _, ok := yk[k]; !ok {
			return false
		}
	}
	return true
}

func capKeySet(caps []CapDecl) map[string]CapDecl {
	m := map[string]CapDecl{}
	for _, c := range caps {
		m[c.Tool+"|"+c.ScopeArg+"|"+c.Pattern+"|"+string(c.Sensitivity)] = c
	}
	return m
}

func capDiff(a, b []CapDecl) []string {
	ak, bk := capKeySet(a), capKeySet(b)
	var out []string
	for k := range ak {
		if _, ok := bk[k]; !ok {
			out = append(out, "removed "+k)
		}
	}
	for k := range bk {
		if _, ok := ak[k]; !ok {
			out = append(out, "added "+k)
		}
	}
	sort.Strings(out)
	return out
}

func equalPaths(a, b []labels.PathRule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Pattern != b[i].Pattern || a[i].Trust != b[i].Trust || a[i].Sensitivity != b[i].Sensitivity {
			return false
		}
	}
	return true
}
