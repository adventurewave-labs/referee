package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sign(t *testing.T, secret, body string, ts int64) (string, string) {
	t.Helper()
	sts := strconv.FormatInt(ts, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + sts + ":" + body))
	return sts, "v0=" + hex.EncodeToString(mac.Sum(nil))
}

// §9: Slack interactive requests are signature-verified, fresh, and
// forwarded to an authorize-then-consume resolve.
func TestSlackInteractiveVerification(t *testing.T) {
	s := NewSlack("xoxb-fake", "signing-secret", "#ops")
	secret := "signing-secret"

	body := `payload={"type":"interactive_message","team":{"id":"T1"},"user":{"id":"U1"},"actions":[{"action_id":"referee_approve:ch-000001"}],"response_url":"https://hooks.slack.com/x"}`
	ts, sig := sign(t, secret, body, time.Now().Unix())

	var resolved *InteractivePayload
	handler := s.HandleInteractive(func(p InteractivePayload) error {
		resolved = &p
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/slack/interactive", strings.NewReader(body))
	req.Header.Set("X-Slack-Request-Timestamp", ts)
	req.Header.Set("X-Slack-Signature", sig)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid signed request must pass, got %d: %s", rec.Code, rec.Body.String())
	}
	if resolved == nil || resolved.ChallengeID != "ch-000001" || resolved.Approver != "U1" || !resolved.Approve {
		t.Fatalf("payload decoded wrong: %+v", resolved)
	}

	// bad signature rejected
	req2 := httptest.NewRequest(http.MethodPost, "/slack/interactive", strings.NewReader(body))
	req2.Header.Set("X-Slack-Request-Timestamp", ts)
	req2.Header.Set("X-Slack-Signature", "v0=deadbeef")
	rec2 := httptest.NewRecorder()
	handler(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature must be rejected, got %d", rec2.Code)
	}

	// stale timestamp rejected (replay > 5 min)
	oldTs, oldSig := sign(t, secret, body, time.Now().Add(-10*time.Minute).Unix())
	req3 := httptest.NewRequest(http.MethodPost, "/slack/interactive", strings.NewReader(body))
	req3.Header.Set("X-Slack-Request-Timestamp", oldTs)
	req3.Header.Set("X-Slack-Signature", oldSig)
	rec3 := httptest.NewRecorder()
	handler(rec3, req3)
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("stale timestamp must be rejected, got %d", rec3.Code)
	}

	// GET rejected (POST-only per Slack interactive contract)
	req4 := httptest.NewRequest(http.MethodGet, "/slack/interactive", nil)
	rec4 := httptest.NewRecorder()
	handler(rec4, req4)
	if rec4.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET must be rejected, got %d", rec4.Code)
	}
}

func TestParseInteractiveDeny(t *testing.T) {
	p, err := ParseInteractive(`{"team":{"id":"T"},"user":{"id":"U9"},"actions":[{"action_id":"referee_deny:ch-000009"}],"response_url":""}`)
	if err != nil || p.ChallengeID != "ch-000009" || p.Approve {
		t.Fatalf("deny parse wrong: %+v %v", p, err)
	}
	if _, err := ParseInteractive(`{"actions":[]}`); err == nil {
		t.Fatalf("payload without actions must error")
	}
}

// an empty signing secret is a publicly computable key: never accepted.
func TestEmptySigningSecretRejected(t *testing.T) {
	body := "payload={}"
	ts, sig := sign(t, "", body, time.Now().Unix())
	if err := VerifySignature("", ts, body, sig); err == nil {
		t.Fatalf("a signature made with an empty secret must be rejected")
	}
}
