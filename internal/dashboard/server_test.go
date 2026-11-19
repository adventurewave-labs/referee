package dashboard

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/adventurewave-labs/referee/internal/challenge"
)

func TestDashboardEndpoints(t *testing.T) {
	mgr := challenge.NewManager(time.Minute, []byte("k"), time.Now)
	s := New(Deps{
		LogPath:    "", // no receipts yet — endpoints must not crash
		Token:      "tok",
		Challenges: mgr,
		Sessions: func() []SessionInfo {
			return []SessionInfo{{ID: "s1", TaskID: "t1", Class: "ops", Blocks: 2, Untrusted: 1, Alive: true}}
		},
	})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// index renders
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	defer resp.Body.Close()
	buf, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(buf), "referee") || !strings.Contains(string(buf), "live sessions") {
		t.Fatalf("index page broken")
	}

	// sessions API
	resp2, err := http.Get(srv.URL + "/api/sessions")
	if err != nil {
		t.Fatalf("sessions: %v", err)
	}
	defer resp2.Body.Close()
	var sessions []SessionInfo
	json.NewDecoder(resp2.Body).Decode(&sessions)
	if len(sessions) != 1 || sessions[0].ID != "s1" {
		t.Fatalf("sessions api broken: %+v", sessions)
	}

	// approvals require the bearer token
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/challenge/ch-000001/resolve",
		strings.NewReader(`{"approver":"U1","approve":true}`))
	resp3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("approve without token must be 401, got %d", resp3.StatusCode)
	}

	// with the token, unknown challenge → 403 (manager rejects)
	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/challenge/ch-999999/resolve",
		strings.NewReader(`{"approver":"U1","approve":true}`))
	req2.Header.Set("Authorization", "Bearer tok")
	resp4, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown challenge must be 403, got %d", resp4.StatusCode)
	}
}
