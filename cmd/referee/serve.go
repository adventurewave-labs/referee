package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/adventurewave-labs/referee/internal/caps"
	"github.com/adventurewave-labs/referee/internal/challenge"
	"github.com/adventurewave-labs/referee/internal/dashboard"
	"github.com/adventurewave-labs/referee/internal/gate"
	"github.com/adventurewave-labs/referee/internal/keys"
	"github.com/adventurewave-labs/referee/internal/labels"
	"github.com/adventurewave-labs/referee/internal/policy"
	"github.com/adventurewave-labs/referee/internal/probe"
	"github.com/adventurewave-labs/referee/internal/proxy"
	"github.com/adventurewave-labs/referee/internal/receipts"
	"github.com/adventurewave-labs/referee/internal/siem"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	mode := fs.String("mode", "stdio", "stdio | http")
	policyPath := fs.String("policy", "", "policy YAML (required)")
	upstreamCmd := fs.String("upstream-cmd", "", "upstream MCP server command (stdio mode)")
	upstreamURL := fs.String("upstream-url", "", "upstream MCP URL (http mode)")
	listen := fs.String("listen", "127.0.0.1:8199", "listen address (http mode)")
	taskID := fs.String("task-id", "", "task id (stdio single-task mode)")
	taskClass := fs.String("task-class", "", "task class (stdio single-task mode)")
	logPath := fs.String("log", "referee-receipts.jsonl", "receipt log path")
	headsPath := fs.String("heads", "referee-heads.jsonl", "receipt batch-heads path")
	seedPath := fs.String("seed", "referee-receipt.seed", "ed25519 receipt-signing seed (created 0600)")
	hmacKeyPath := fs.String("hmac-key", ".args-hmac-key", "args-HMAC key file (created 0600; overridden by $REF_RECEIPT_HMAC)")
	challengeMode := fs.String("challenge-mode", "local", "local | slack")
	challengeTimeout := fs.Duration("challenge-timeout", 5*time.Minute, "challenge deadline (timeout = default deny)")
	slackChannel := fs.String("slack-channel", "", "slack channel for challenges")
	slackHook := fs.String("slack-hook-addr", "127.0.0.1:8201", "listen address for slack interactive endpoint")
	siemEndpoint := fs.String("siem-endpoint", "", "OTLP/HTTP base URL: continuously tail receipts to the SIEM (best-effort)")
	dashAddr := fs.String("dashboard", "", "dashboard address (local challenge mode defaults to 127.0.0.1:8200)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *policyPath == "" {
		return fmt.Errorf("serve: --policy is required")
	}
	pol, err := policy.Load(*policyPath)
	if err != nil {
		return err
	}

	// judges from policy (§5.1 influence probe)
	var judges []probe.Judge
	for _, jc := range pol.Judges {
		j, err := probe.NewHTTPJudge(jc.Provider, jc.Model, jc.Endpoint, jc.APIKeyEnv)
		if err != nil {
			return fmt.Errorf("serve: judge %q: %w", jc.Name, err)
		}
		judges = append(judges, j)
	}
	var prb *probe.Probe
	if len(judges) > 0 {
		prb = probe.New(judges, pol.Defaults.ProbeTimeout.D(), time.Now)
	}

	// keys + receipts (§5.4)
	hmacKey, err := keys.LoadOrCreateHMAC(os.Getenv("REF_RECEIPT_HMAC"), *hmacKeyPath)
	prb.WithholdKey = hmacKey // keyed refs for withheld high content in judge prompts
	if err != nil {
		return err
	}
	priv, pub, err := keys.LoadOrCreateSigning(*seedPath)
	if err != nil {
		return err
	}
	// export the receipt pubkey: verify/dashboard need it to check batch-head
	// signatures — without an exported key they silently degrade to the
	// unkeyed chain, and a recomputed-hash rewrite would read OK (finding #3)
	if err := os.WriteFile("referee-pubkey.hex", []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return fmt.Errorf("serve: writing receipt pubkey: %w", err)
	}
	rcp, err := receipts.Open(*logPath, *headsPath, hmacKey, priv, 100)
	if err != nil {
		return err
	}

	g := &gate.Gate{Policy: pol, Matcher: labels.NewMatcher(), Classifier: labels.DefaultClassifier(), Probe: prb}
	capsStore := caps.NewStore(time.Now)
	mgr := challenge.NewManager(*challengeTimeout, hmacKey, time.Now)
	logger := log.New(os.Stderr, "referee ", log.LstdFlags)

	eng := &proxy.Engine{Policy: pol, Gate: g, Caps: capsStore, Receipts: rcp, Challenges: mgr, ReceiptKey: hmacKey, Log: logger,
		ControlToken: []byte(os.Getenv("REF_CONTROL_TOKEN")),
	PolicyHash:   pol.Hash(),
	}

	// challenge dispatch: slack buttons or local (dashboard/CLI approver)
	var slack *challenge.SlackNotifier
	switch *challengeMode {
	case "slack":
		botToken, signSecret := os.Getenv("REF_SLACK_BOT_TOKEN"), os.Getenv("REF_SLACK_SIGNING_SECRET")
		if botToken == "" || signSecret == "" || *slackChannel == "" {
			return fmt.Errorf("serve: slack mode needs REF_SLACK_BOT_TOKEN, REF_SLACK_SIGNING_SECRET and --slack-channel")
		}
		slack = challenge.NewSlack(botToken, signSecret, *slackChannel)
		eng.Notifier = slack.Notify
	case "local":
		eng.Notifier = func(c challenge.Challenge) error {
			logger.Printf("CHALLENGE %s pending: tool=%s rule=%s — approve: referee approve --challenge-id %s (or the dashboard)",
				c.ID, c.Tool, c.Rule, c.ID)
			return nil
		}
	default:
		return fmt.Errorf("serve: unknown challenge-mode %q", *challengeMode)
	}

	// dashboard + local approver surface. The token never travels argv or
	// logs (repo invariant): REF_DASHBOARD_TOKEN env, else generated into a
	// 0600 file whose PATH — never its contents — is logged (finding #1).
	dashToken := os.Getenv("REF_DASHBOARD_TOKEN")
	if dashToken == "" {
		dashToken = randomToken()
		const tpath = "referee-dashboard-token"
		if err := os.WriteFile(tpath, []byte(dashToken+"\n"), 0o600); err != nil {
			return fmt.Errorf("serve: writing dashboard token file: %w", err)
		}
		logger.Printf("dashboard token (generated) written to %s (0600)", tpath)
	}
	registry := proxy.NewRegistry()
	registry.WithAlive(func(task string) bool { return eng.Caps.Get(task) != nil })

	// SIEM tailer (§6 P1): best-effort export of every new receipt; SIEM
	// availability never influences gate behavior — failures are logged, the
	// receipt log on disk stays the source of truth.
	if err := refuseCredentialedEndpoint(*siemEndpoint, "serve"); err != nil {
		return err
	}
	if *siemEndpoint != "" {
		// auth via env only (round-39): REF_SIEM_AUTH carries the full
		// Authorization value; the endpoint URL is never logged (it may
		// carry query-string tokens)
		var hdr map[string]string
		if v := os.Getenv("REF_SIEM_AUTH"); v != "" {
			hdr = map[string]string{"Authorization": v}
		}
		tl := &siem.Tailer{Log: siem.New(*siemEndpoint, hdr), LogPath: *logPath, Interval: 5 * time.Second,
			Report: func(err error) { logger.Printf("siem: export failed (will retry): %v", err) }}
		stop := make(chan struct{})
		defer close(stop)
		go func() { _ = tl.Run(stop) }()
		logger.Printf("siem export: tailing %s (endpoint configured, details not logged)", *logPath)
	}
	dash := dashboard.New(dashboard.Deps{
		LogPath: *logPath, HeadsPath: *headsPath, PubKey: pub, Token: dashToken,
		ReceiptsKey: hmacKey, Challenges: mgr,
		Sessions: func() []dashboard.SessionInfo {
			stats := registry.Stats()
			out := make([]dashboard.SessionInfo, len(stats))
			for i, st := range stats {
				out[i] = dashboard.SessionInfo(st)
			}
			return out
		},
	})
	dashAddrEff := *dashAddr
	if dashAddrEff == "" && *challengeMode == "local" {
		dashAddrEff = "127.0.0.1:8200"
	}
	if dashAddrEff != "" {
		mux := http.NewServeMux()
		mux.Handle("/", dash.Handler())
		go func() {
			logger.Printf("dashboard on http://%s (token required for approvals)", dashAddrEff)
			if err := http.ListenAndServe(dashAddrEff, mux); err != nil {
				logger.Printf("dashboard: %v", err)
			}
		}()
	}

	// slack interactive endpoint: its own listener so it works whether or
	// not the dashboard is enabled (signed requests only, see HandleInteractive)
	if slack != nil {
		smux := http.NewServeMux()
		smux.HandleFunc("/slack/interactive", slack.HandleInteractive(func(p challenge.InteractivePayload) error {
			return mgr.Resolve(p.ChallengeID, p.Approver, p.Approve)
		}))
		go func() {
			logger.Printf("slack interactive endpoint on http://%s/slack/interactive", *slackHook)
			if err := http.ListenAndServe(*slackHook, smux); err != nil {
				logger.Printf("slack endpoint: %v", err)
			}
		}()
	}

	switch *mode {
	case "stdio":
		return serveStdio(eng, registry, *upstreamCmd, *taskID, *taskClass, logger)
	case "http":
		eng.Log.Printf("http middleware on %s → %s", *listen, *upstreamURL)
		return proxy.RunHTTP(eng, *listen, *upstreamURL)
	default:
		return fmt.Errorf("serve: unknown mode %q", *mode)
	}
}

func serveStdio(eng *proxy.Engine, registry *proxy.Registry, upstreamCmd, taskID, class string, logger *log.Logger) error {
	if upstreamCmd == "" {
		return fmt.Errorf("serve: stdio mode needs --upstream-cmd")
	}
	rwc, cmd, err := proxy.SpawnUpstream(upstreamCmd)
	if err != nil {
		return err
	}
	defer func() {
		_ = rwc.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	sess := proxy.NewSession("stdio", eng.Policy.Registry)
	registry.Add(sess)
	if taskID != "" || class != "" {
		if class == "" {
			return fmt.Errorf("serve: --task-class required with --task-id")
		}
		if err := eng.StartTask(sess, taskID, class, nil, ""); err != nil {
			return err
		}
	}
	defer eng.EndTask(sess) // immediate revocation on process end (§5.2)
	logger.Printf("stdio proxy: agent=stdin upstream=%q", upstreamCmd)
	return proxy.RunStdioSession(eng, sess, os.Stdin, os.Stdout, rwc)
}

func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "referee-local-" + fmt.Sprint(time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
