// Command referee is the MCP middleware proxy CLI (PRD §6):
//
//	referee serve    — run the proxy (stdio or streamable-HTTP)
//	referee verify   — verify a receipt log chain + batch-head signatures
//	referee why      — explain a decision from the receipt log
//	referee policy   — check / dry-run diff policy files
//	referee demo     — self-contained end-to-end scenario (§8)
//	referee approve  — resolve a pending challenge via the local dashboard
package main

import (
	"fmt"
	"os"
)

func usage(w *os.File) {
	fmt.Fprintf(w, `referee — taint-tracking & task-scoped authorization middleware for agents

usage:
  referee serve --policy p.yaml [--mode stdio|http] [--upstream-cmd "cmd args"]
                [--upstream-url URL] [--listen 127.0.0.1:8199]
                [--task-id ID --task-class CLASS] [--challenge-mode local|slack] [--slack-channel C] [--slack-hook-addr ADDR]
                [--dashboard 127.0.0.1:8200]
                [--log referee-receipts.jsonl] [--heads referee-heads.jsonl]
                [--seed referee-receipt.seed] [--hmac-key .args-hmac-key]
  referee verify --log FILE [--heads FILE] [--pubkey FILE]
  referee why --log FILE [--task T] [--tool T] [--decision D] [--rule R]
  referee policy check --policy p.yaml
  referee policy diff --policy a.yaml --policy b.yaml
  referee demo
  referee approve --addr 127.0.0.1:8200 --challenge-id ID
                  --approver NAME [--allow | --deny]

environment:
  REF_RECEIPT_HMAC            args-HMAC key (hex or raw) — else --hmac-key file
  REF_DASHBOARD_TOKEN         dashboard bearer token — else generated into
                              referee-dashboard-token (0600); never argv/logs
  REF_SLACK_BOT_TOKEN         slack bot token (challenge-mode slack)
  REF_SLACK_SIGNING_SECRET    slack signing secret

secrets never enter git, argv, or logs (rig law 9 / PRD §9).
`)
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "why":
		err = cmdWhy(os.Args[2:])
	case "policy":
		err = cmdPolicy(os.Args[2:])
	case "demo":
		err = runDemo(os.Stdout)
	case "tune":
		err = cmdTune(os.Args[2:])
	case "export":
		err = cmdExport(os.Args[2:])
	case "approve":
		err = cmdApprove(os.Args[2:])
	case "help", "-h", "--help":
		usage(os.Stdout)
		return
	default:
		fmt.Fprintf(os.Stderr, "referee: unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "referee: %v\n", err)
		os.Exit(1)
	}
}
