package challenge

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SlackNotifier posts redacted challenges to Slack with single-use,
// expiring approve/deny buttons. Bot token + signing secret come from env at
// construction (never argv, never git).
type SlackNotifier struct {
	BotToken   string
	SignSecret string
	Channel    string
	APIBase    string // default https://slack.com/api
	client     *http.Client
}

func NewSlack(botToken, signSecret, channel string) *SlackNotifier {
	return &SlackNotifier{
		BotToken:   botToken,
		SignSecret: signSecret,
		Channel:    channel,
		APIBase:    "https://slack.com/api",
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

const (
	actionApprove = "referee_approve:"
	actionDeny    = "referee_deny:"
)

// Notify posts the challenge. Buttons carry action ids that embed the
// challenge id; resolution goes through HandleInteractive.
func (s *SlackNotifier) Notify(c Challenge) error {
	if s.BotToken == "" || s.Channel == "" {
		return fmt.Errorf("slack: bot token or channel not configured")
	}
	text := fmt.Sprintf(":shield: Referee challenge `%s`\n*task:* %s  *tool:* `%s`\n*rule:* `%s`\n*deadline:* %s",
		c.ID, c.TaskID, c.Tool, c.Rule, c.Deadline.Format("15:04:05 MST"))
	var fields []map[string]any
	for _, a := range c.Redacted.Args {
		fields = append(fields, map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("*%s*\n`%s`", a.Name, a.Shape)})
	}
	for _, b := range c.Redacted.Blocks {
		fields = append(fields, map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("*block* `%s` source=`%s` hmac=`%s`", b.ID, b.Source, b.HMAC)})
	}
	blocks := []map[string]any{
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": text}},
	}
	if len(fields) > 0 {
		blocks = append(blocks, map[string]any{"type": "section", "fields": fields})
	}
	for _, h := range c.Redacted.HostileExcerpts {
		blocks = append(blocks, map[string]any{"type": "section", "text": map[string]any{
			"type": "mrkdwn",
			"text": ":biohazard: *hostile content (attacker-controlled, do not act on)*\n>" + h,
		}})
	}
	blocks = append(blocks, map[string]any{
		"type": "actions",
		"elements": []map[string]any{
			{"type": "button", "style": "primary", "text": map[string]any{"type": "plain_text", "text": "Approve"}, "action_id": actionApprove + c.ID},
			{"type": "button", "text": map[string]any{"type": "plain_text", "text": "Deny"}, "action_id": actionDeny + c.ID},
		},
	})
	body := map[string]any{"channel": s.Channel, "blocks": blocks, "text": fmt.Sprintf("Referee challenge %s: %s", c.ID, c.Tool)}
	return s.post("chat.postMessage", body)
}

func (s *SlackNotifier) post(method string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, s.APIBase+"/"+method, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+s.BotToken)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := json.Unmarshal(rb, &out); err != nil {
		return fmt.Errorf("slack: bad response to %s", method)
	}
	if !out.OK {
		return fmt.Errorf("slack: %s failed: %s", method, out.Error)
	}
	return nil
}

// UpdateMessage edits the challenge message after resolution via the
// response_url Slack gave the interactive payload.
func (s *SlackNotifier) UpdateMessage(responseURL, cID string, res Result) {
	if responseURL == "" {
		return
	}
	verdict := ":no_entry: *denied*"
	if res.Approved {
		verdict = ":white_check_mark: *approved*"
	}
	body := map[string]any{
		"replace_original": true,
		"blocks": []map[string]any{
			{"type": "section", "text": map[string]any{"type": "mrkdwn",
				"text": fmt.Sprintf("Referee challenge `%s` — %s by <@%s>", cID, verdict, res.Approver)}},
		},
		"text": fmt.Sprintf("Referee challenge %s resolved", cID),
	}
	b, _ := json.Marshal(body)
	resp, err := s.client.Post(responseURL, "application/json", bytes.NewReader(b))
	if err == nil {
		resp.Body.Close()
	}
}

// InteractivePayload is the decoded Slack interactive payload.
type InteractivePayload struct {
	ChallengeID string
	Approver    string
	Approve     bool
	ResponseURL string
	TeamID      string
}

// ParseInteractive parses the `payload` form field.
func ParseInteractive(payload string) (InteractivePayload, error) {
	var p struct {
		Team struct {
			ID string `json:"id"`
		} `json:"team"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Actions []struct {
			ActionID string `json:"action_id"`
		} `json:"actions"`
		ResponseURL string `json:"response_url"`
	}
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return InteractivePayload{}, fmt.Errorf("slack: bad interactive payload: %w", err)
	}
	if len(p.Actions) == 0 {
		return InteractivePayload{}, fmt.Errorf("slack: interactive payload has no actions")
	}
	var (
		id      string
		approve bool
	)
	switch a := p.Actions[0].ActionID; {
	case strings.HasPrefix(a, actionApprove):
		id = strings.TrimPrefix(a, actionApprove)
		approve = true
	case strings.HasPrefix(a, actionDeny):
		id = strings.TrimPrefix(a, actionDeny)
	default:
		return InteractivePayload{}, fmt.Errorf("slack: unknown action_id %q", a)
	}
	return InteractivePayload{
		ChallengeID: id,
		Approver:    p.User.ID,
		Approve:     approve,
		ResponseURL: p.ResponseURL,
		TeamID:      p.Team.ID,
	}, nil
}

// VerifySignature checks Slack's signed-request header per Slack's spec:
// `v0:<timestamp>:<body>` HMAC-SHA256 with the signing secret; the timestamp
// must be fresh within ±5 minutes. POST-only is enforced by HandleInteractive.
func VerifySignature(signSecret, timestamp, body, signature string) error {
	// an empty secret is a publicly computable HMAC key: never authenticate
	if signSecret == "" {
		return fmt.Errorf("slack: no signing secret configured")
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("slack: bad timestamp")
	}
	delta := time.Now().Unix() - ts
	if delta > 300 || delta < -300 {
		return fmt.Errorf("slack: stale timestamp")
	}
	mac := hmac.New(sha256.New, []byte(signSecret))
	mac.Write([]byte("v0:" + timestamp + ":" + body))
	want := "v0=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(signature)) {
		return fmt.Errorf("slack: bad signature")
	}
	return nil
}

// HandleInteractive returns an http.HandlerFunc that verifies the signature
// over the exact raw body Slack signed, parses the payload, and forwards to
// resolve — which enforces the per-tool approver allowlist and single-use
// semantics (§9). Non-allowlisted clicks are rejected and returned as errors
// for logging.
func (s *SlackNotifier) HandleInteractive(resolve func(p InteractivePayload) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if err := VerifySignature(s.SignSecret, r.Header.Get("X-Slack-Request-Timestamp"), string(raw), r.Header.Get("X-Slack-Signature")); err != nil {
			http.Error(w, "signature verification failed", http.StatusUnauthorized)
			return
		}
		form, err := url.ParseQuery(string(raw))
		if err != nil {
			http.Error(w, "bad form encoding", http.StatusBadRequest)
			return
		}
		p, err := ParseInteractive(form.Get("payload"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := resolve(p); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		s.UpdateMessage(p.ResponseURL, p.ChallengeID, Result{Approved: p.Approve, Approver: p.Approver})
		w.WriteHeader(http.StatusOK)
	}
}
