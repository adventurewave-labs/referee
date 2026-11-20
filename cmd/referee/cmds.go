package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/adventurewave-labs/referee/internal/demo"
	"github.com/adventurewave-labs/referee/internal/keys"
	"github.com/adventurewave-labs/referee/internal/policy"
	"github.com/adventurewave-labs/referee/internal/receipts"
	"github.com/adventurewave-labs/referee/internal/observe"
	"github.com/adventurewave-labs/referee/internal/siem"
)

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	logPath := fs.String("log", "referee-receipts.jsonl", "receipt log path")
	headsPath := fs.String("heads", "referee-heads.jsonl", "batch-heads path")
	pubPath := fs.String("pubkey", "referee-pubkey.hex", "ed25519 public key file (hex); batch heads checked when given")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, err := keys.LoadPubKey(*pubPath)
	if err != nil {
		return err
	}
	if pub == nil && headsHaveContent(*headsPath) {
		// no key: a log rewritten with recomputed hashes would print OK —
		// refuse the unsigned check instead of degrading silently
		return fmt.Errorf("verify: %s has entries but no pubkey was loaded — pass --pubkey", *headsPath)
	}
	n, heads, err := receipts.Verify(*logPath, *headsPath, pub)
	if err != nil {
		return fmt.Errorf("verify FAILED: %w", err)
	}
	fmt.Printf("OK: %d entries verified, %d batch heads checked\n", n, heads)
	return nil
}

// headsHaveContent reports whether the heads file exists and is non-empty.
func headsHaveContent(path string) bool {
	b, err := os.ReadFile(path)
	return err == nil && len(bytes.TrimSpace(b)) > 0
}

func cmdWhy(args []string) error {
	fs := flag.NewFlagSet("why", flag.ExitOnError)
	logPath := fs.String("log", "referee-receipts.jsonl", "receipt log path")
	task := fs.String("task", "", "filter by task id")
	tool := fs.String("tool", "", "filter by tool")
	decision := fs.String("decision", "", "filter by decision (approve|challenge|deny)")
	rule := fs.String("rule", "", "filter by rule substring")
	if err := fs.Parse(args); err != nil {
		return err
	}
	entries, err := receipts.Search(*logPath, *task, *tool, *decision, *rule)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("no matching decisions in the log")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "seq\ttime\ttask\ttool\tdecision\trule\tapprover\taxis\tblocks")
	for _, e := range entries {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			e.Seq, e.TS.Format("01-02 15:04:05"), e.Task, e.Tool, e.Decision, e.Rule,
			e.Approver, e.Axis, joinIDs(e.BlockIDs))
	}
	w.Flush()
	fmt.Printf("\n%d matching decisions; args are HMAC-only (use --rule to find the firing clause)\n", len(entries))
	return nil
}

func joinIDs(ids []string) string {
	if len(ids) == 0 {
		return "-"
	}
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += ","
		}
		out += id
	}
	return out
}

func cmdPolicy(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("policy: need a subcommand (check | diff)")
	}
	switch args[0] {
	case "check":
		fs := flag.NewFlagSet("policy check", flag.ExitOnError)
		path := fs.String("policy", "", "policy YAML (required)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *path == "" {
			return fmt.Errorf("policy check: --policy required")
		}
		p, err := policy.Load(*path)
		if err != nil {
			return err
		}
		fmt.Printf("OK: %d tools, %d task classes, %d path rules, %d judges\n",
			len(p.Tools), len(p.Tasks), len(p.Registry.PathRules), len(p.Judges))
		return nil
	case "diff":
		fs := flag.NewFlagSet("policy diff", flag.ExitOnError)
		a := fs.String("policy", "", "current policy (required)")
		b := fs.String("against", "", "candidate policy (required)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *a == "" || *b == "" {
			return fmt.Errorf("policy diff: --policy and --against required")
		}
		pa, err := policy.Load(*a)
		if err != nil {
			return err
		}
		pb, err := policy.Load(*b)
		if err != nil {
			return err
		}
		fmt.Println(policy.Diff(pa, pb))
		return nil
	default:
		return fmt.Errorf("policy: unknown subcommand %q (check | diff)", args[0])
	}
}

func cmdApprove(args []string) error {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8200", "dashboard address")
	id := fs.String("challenge-id", "", "challenge id (required)")
	approver := fs.String("approver", os.Getenv("USER"), "approver name (must be on the tool allowlist)")
	allow := fs.Bool("allow", false, "approve")
	deny := fs.Bool("deny", false, "deny")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("approve: --challenge-id required")
	}
	if *allow == *deny {
		return fmt.Errorf("approve: exactly one of --allow / --deny")
	}
	token := os.Getenv("REF_DASHBOARD_TOKEN")
	if token == "" {
		if b, err := os.ReadFile("referee-dashboard-token"); err == nil {
			token = string(bytes.TrimSpace(b))
		}
	}
	if token == "" {
		return fmt.Errorf("approve: no dashboard token — set REF_DASHBOARD_TOKEN (or run where serve wrote referee-dashboard-token)")
	}
	body, _ := json.Marshal(map[string]any{"approver": *approver, "approve": *allow})
	url := fmt.Sprintf("http://%s/api/challenge/%s/resolve", *addr, *id)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var b bytes.Buffer
		_, _ = b.ReadFrom(resp.Body)
		return fmt.Errorf("approve: dashboard said %d: %s", resp.StatusCode, b.String())
	}
	fmt.Printf("challenge %s resolved by %s (approve=%t)\n", *id, *approver, *allow)
	return nil
}

func runDemo(w *os.File) error {
	return demo.Run(w)
}

// cmdExport ships receipt-log entries to an OTLP/HTTP SIEM endpoint
// (PRD §6 P1). One-shot: entries from --seq-start (default all) ship once;
// use serve --siem-endpoint for continuous tailing.
func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	logPath := fs.String("log", "referee-receipts.jsonl", "receipt log path")
	endpoint := fs.String("endpoint", "", "OTLP/HTTP base URL (required, e.g. http://siem:4318)")
	seqStart := fs.Int("seq-start", 1, "first seq to export (1 = all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *endpoint == "" {
		return fmt.Errorf("export: --endpoint required")
	}
	// the flag VALUE sits in argv (visible in process listings): refuse
	// query-bearing and userinfo-bearing endpoints; credentials belong in
	// REF_SIEM_AUTH (round-61/63)
	if err := refuseCredentialedEndpoint(*endpoint, "export"); err != nil {
		return err
	}
	// SIEM auth travels via env only — never argv (rig invariant; round-36:
	// a --header k=v flag invited tokens into process listings)
	var hdr map[string]string
	if v := os.Getenv("REF_SIEM_AUTH"); v != "" {
		hdr = map[string]string{"Authorization": v}
	}
	entries, err := receipts.ReadAll(*logPath)
	if err != nil {
		return err
	}
	var batch []receipts.Entry
	for _, e := range entries {
		if int(e.Seq) >= *seqStart {
			batch = append(batch, e)
		}
	}
	if len(batch) == 0 {
		fmt.Println("export: nothing to ship at or after seq", *seqStart)
		return nil
	}
	// bounded batches (as the Tailer does): a large backlog must drain in
	// many POSTs, never one that outlives every client timeout
	x := siem.New(*endpoint, hdr)
	const batchSize = 500
	shipped := 0
	for shipped < len(batch) {
		end := shipped + batchSize
		if end > len(batch) {
			end = len(batch)
		}
		if err := x.Ship(batch[shipped:end]); err != nil {
			return fmt.Errorf("export: shipped %d of %d entries before failing: %w", shipped, len(batch), err)
		}
		shipped = end
	}
	fmt.Printf("export: shipped %d entries (seq %d..%d) to the endpoint\n", len(batch), batch[0].Seq, batch[len(batch)-1].Seq)
	return nil
}

// refuseCredentialedEndpoint rejects SIEM endpoint flags that carry
// credentials: query strings and user:token@host userinfo both sit in argv,
// where they are process-listing visible. Credentials belong in the
// REF_SIEM_AUTH environment variable (Authorization header).
func refuseCredentialedEndpoint(endpoint, cmd string) error {
	if strings.Contains(endpoint, "?") {
		return fmt.Errorf("%s: endpoint must not contain a query string — put credentials in $REF_SIEM_AUTH (Authorization header), not the URL", cmd)
	}
	if strings.Contains(endpoint, "@") {
		return fmt.Errorf("%s: endpoint must not contain user:token@host userinfo — put credentials in $REF_SIEM_AUTH (Authorization header), not the URL", cmd)
	}
	return nil
}

// cmdObserve analyzes a receipt log against the policy and prints tuning
// evidence: cost profile (probe decisions), cap gaps, unused caps, tightening
// suggestions (PRD §12 — suggestions, not auto-remediation).
func cmdObserve(args []string) error {
	fs := flag.NewFlagSet("observe", flag.ExitOnError)
	logPath := fs.String("log", "referee-receipts.jsonl", "receipt log path")
	policyPath := fs.String("policy", "", "policy YAML (optional; enables unused-cap detection)")
	taskClasses := map[string]string{}
	fs.Var(taskClassMap(taskClasses), "task-class", "task-id=class attribution (repeatable; REQUIRED for unused-cap detection)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// read ONCE, verify THAT exact slice: verify-then-reread has a TOCTOU
	// gap (the file can change between reads — round-81, codex)
	// load/validate the policy FIRST: an empty log must not mask a missing
	// or malformed --policy (round-75)
	var pol *policy.Policy
	if *policyPath != "" {
		var err error
		if pol, err = policy.Load(*policyPath); err != nil {
			return fmt.Errorf("observe: --policy: %w", err)
		}
	}
	entries, err := receipts.ReadAll(*logPath)
	if err != nil {
		return err
	}
	if err := receipts.VerifyEntries(entries); err != nil {
		return fmt.Errorf("observe: receipt log failed verification: %w", err)
	}
	if len(entries) == 0 {
		fmt.Println("observe: receipt log empty — run some gated traffic first")
		return nil
	}
	rep := observe.Analyze(entries)
	fmt.Printf("observed %d decisions across %d tools\n\n", rep.Entries, len(rep.Tools))
	for _, ts := range rep.Tools {
		fmt.Printf("  %-28s calls=%-4d approve=%-4d challenge=%-3d deny=%-3d probe=%d capgaps=%d\n",
			ts.Tool, ts.Calls, ts.Approved, ts.Challenged, ts.Denied, ts.ProbeDecided, ts.CapGaps)
	}
	fmt.Println("\n— suggestions —")
	var polHash string
	if pol != nil {
		polHash = pol.Hash()
	}
	for _, s := range observe.SuggestNarrowingWithTasks(rep, pol, entries, taskClasses, polHash) {
		fmt.Println("  " + s)
	}
	return nil
}

// taskClassMap implements flag.Value accumulating task-id=class pairs.
type taskClassMap map[string]string

func (m taskClassMap) String() string {
	if m == nil {
		return ""
	}
	var out []string
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return strings.Join(out, ",")
}

func (m taskClassMap) Set(v string) error {
	parts := strings.SplitN(v, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("task-class wants task-id=class, got %q", v)
	}
	if strings.TrimSpace(parts[1]) == "" {
		return fmt.Errorf("task-class: class value must not be empty (task %q) — empty classes hide grants", parts[0])
	}
	if strings.TrimSpace(parts[0]) == "" {
		return fmt.Errorf("task-class: task id must not be empty")
	}
	if prev, dup := m[parts[0]]; dup && prev != parts[1] {
		// conflicting duplicates misattribute approvals and falsely mark the
		// actual class's grants unused (round-81)
		return fmt.Errorf("task-class: conflicting mapping for task %q (%q vs %q) — pass one mapping", parts[0], prev, parts[1])
	}
	m[parts[0]] = parts[1]
	return nil
}
