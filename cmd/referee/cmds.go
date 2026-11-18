package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/adventurewave-labs/referee/internal/demo"
	"github.com/adventurewave-labs/referee/internal/keys"
	"github.com/adventurewave-labs/referee/internal/policy"
	"github.com/adventurewave-labs/referee/internal/receipts"
)

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	logPath := fs.String("log", "referee-receipts.jsonl", "receipt log path")
	headsPath := fs.String("heads", "referee-heads.jsonl", "batch-heads path")
	pubPath := fs.String("pubkey", "", "ed25519 public key file (hex); head signatures checked when given")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, err := keys.LoadPubKey(*pubPath)
	if err != nil {
		return err
	}
	n, heads, err := receipts.Verify(*logPath, *headsPath, pub)
	if err != nil {
		return fmt.Errorf("verify FAILED: %w", err)
	}
	fmt.Printf("OK: %d entries verified, %d batch heads checked\n", n, heads)
	return nil
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
	token := fs.String("token", os.Getenv("REF_DASHBOARD_TOKEN"), "dashboard bearer token")
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
	body, _ := json.Marshal(map[string]any{"approver": *approver, "approve": *allow})
	url := fmt.Sprintf("http://%s/api/challenge/%s/resolve", *addr, *id)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+*token)
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
