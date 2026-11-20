package siem

import (
	"fmt"
	"os"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adventurewave-labs/referee/internal/receipts"
)

func tempLog(t *testing.T) (string, *receipts.Log) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	l, err := receipts.Open(path, "", []byte("siem-test-key"), nil, 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return path, l
}

// sampleEntries: one approve + one deny (undeclared-tool HMAC name)
func sampleEntries() []receipts.Entry {
	now := time.Unix(1_700_000_000, 0).UTC()
	return []receipts.Entry{
		{Seq: 1, TS: now, Task: "t1", Tool: "send_email", Rule: "auto:clean(integrity:pass,conf:pass)",
			Decision: "approve", Axis: "integrity=not-detected conf=normal",
			ArgsHMAC: "h1", PrevHash: "genesis", Hash: "x1"},
		{Seq: 2, TS: now, Task: "t1", Tool: "undeclared:abcd1234ef56", Rule: "cap:missing",
			Decision: "deny", Axis: "integrity=unchecked conf=unchecked",
			ArgsHMAC: "h2", PrevHash: "x1", Hash: "x2"},
	}
}

// bodyRecorder captures raw request bodies; the endpoint can toggle down
type bodyRecorder struct {
	mu   sync.Mutex
	text string
	down bool
}

func (b *bodyRecorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		b.text = string(raw)
		w.WriteHeader(http.StatusOK)
	}
}

func (b *bodyRecorder) body() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.text
}

func (b *bodyRecorder) setDown(v bool) {
	b.mu.Lock()
	b.down = v
	b.mu.Unlock()
}

// the OTLP/HTTP JSON payload: shape, service name, severity mapping,
// attribute coverage, and the HMAC-only (no raw args) guarantee
func TestToOTLPPayload(t *testing.T) {
	rec := &bodyRecorder{}
	ts := httptest.NewServer(rec.handler())
	defer ts.Close()

	if err := New(ts.URL, map[string]string{"Authorization": "Bearer siem-token"}).Ship(sampleEntries()); err != nil {
		t.Fatalf("ship: %v", err)
	}

	var payload struct {
		ResourceLogs []struct {
			Resource struct {
				Attributes []struct {
					Key   string `json:"key"`
					Value struct {
						StringValue string `json:"stringValue"`
					} `json:"value"`
				} `json:"attributes"`
			} `json:"resource"`
			ScopeLogs []struct {
				LogRecords []struct {
					TimeUnixNano string `json:"timeUnixNano"`
					SeverityText string `json:"severityText"`
					Attributes   []struct {
						Key   string `json:"key"`
						Value struct {
							StringValue string `json:"stringValue"`
						} `json:"value"`
					} `json:"attributes"`
					Body struct {
						KVList struct {
							Values []struct {
								Key   string `json:"key"`
								Value struct {
									StringValue string `json:"stringValue"`
								} `json:"value"`
							} `json:"values"`
						} `json:"kvlistValue"`
					} `json:"body"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal([]byte(rec.body()), &payload); err != nil {
		t.Fatalf("payload not valid OTLP JSON: %v\n%s", err, rec.body())
	}
	if len(payload.ResourceLogs) != 1 {
		t.Fatalf("want one resourceLogs entry")
	}
	hasService := false
	for _, a := range payload.ResourceLogs[0].Resource.Attributes {
		if a.Key == "service.name" && a.Value.StringValue == "referee" {
			hasService = true
		}
	}
	if !hasService {
		t.Fatalf("service.name=referee attribute missing")
	}
	recs := payload.ResourceLogs[0].ScopeLogs[0].LogRecords
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	if recs[0].SeverityText != "INFO" || recs[1].SeverityText != "WARN" {
		t.Fatalf("severity mapping wrong: %s / %s", recs[0].SeverityText, recs[1].SeverityText)
	}
	if recs[0].TimeUnixNano == "" {
		t.Fatalf("timeUnixNano missing")
	}
	// body is a VALID AnyValue kvlist (round-38)
	if len(recs[0].Body.KVList.Values) == 0 {
		t.Fatalf("body must be a kvlistValue AnyValue: %+v", recs[0].Body)
	}
	hasEvent := false
	for _, kv := range recs[0].Body.KVList.Values {
		if kv.Key == "event" && kv.Value.StringValue == "referee.gate_decision" {
			hasEvent = true
		}
	}
	if !hasEvent {
		t.Fatalf("body kvlist missing event key")
	}
	attrs := map[string]string{}
	for _, a := range recs[1].Attributes {
		attrs[a.Key] = a.Value.StringValue
	}
	for _, k := range []string{"referee.seq", "referee.decision", "referee.args_hmac", "referee.hash", "referee.tool", "referee.rule"} {
		if _, ok := attrs[k]; !ok {
			t.Fatalf("attribute %s missing: %v", k, attrs)
		}
	}
	if attrs["referee.decision"] != "deny" || attrs["referee.seq"] != "2" {
		t.Fatalf("attributes wrong: %v", attrs)
	}
	// HMAC-only by construction: no raw-argument keys anywhere in the payload
	if strings.Contains(rec.body(), `"arguments"`) || strings.Contains(rec.body(), `"args":`) {
		t.Fatalf("EXPORT INVENTED RAW ARGUMENTS: %s", rec.body())
	}
}

// endpoint failures are reported with status, not swallowed
func TestShipFailureReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	err := New(srv.URL, nil).Ship(sampleEntries())
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("endpoint failure must be reported with status, got %v", err)
	}
}

// tailer ships new entries only, survives endpoint failures, and stops clean
func TestTailerShipsNewEntriesOnly(t *testing.T) {
	logPath, l := tempLog(t)
	l.Append(receipts.Record{Task: "t1", Tool: "send_email", Rule: "r1", Decision: "approve", ArgsCanonical: `{}`})

	rec := &bodyRecorder{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	var failures int
	tl := &Tailer{Log: New(srv.URL, nil), LogPath: logPath, Interval: 25 * time.Millisecond,
		Report: func(err error) { failures++ }}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- tl.Run(stop) }()

	shipped := func() string {
		return rec.body() // the recorder keeps the LAST successful body only
	}

	// entry 1 ships (its rule attribute is "r1")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(shipped(), `"stringValue":"r1"`) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(shipped(), `"stringValue":"r1"`) {
		t.Fatalf("first entry never shipped")
	}

	// endpoint goes down, a new entry lands, endpoint comes back: the tailer
	// must keep retrying (failures reported) and never lose the cursor
	rec.setDown(true)
	l.Append(receipts.Record{Task: "t1", Tool: "send_email", Rule: "r2", Decision: "deny", ArgsCanonical: `{}`})
	time.Sleep(100 * time.Millisecond) // at least one failing tick
	rec.setDown(false)

	for time.Now().Before(deadline) && !strings.Contains(shipped(), `"stringValue":"r2"`) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(shipped(), `"stringValue":"r2"`) {
		t.Fatalf("second entry never shipped after recovery")
	}

	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("tailer did not stop")
	}
	if failures == 0 {
		t.Fatalf("endpoint failures must reach the reporter")
	}
}

// empty batch: Ship is a no-op success
func TestShipEmptyNoop(t *testing.T) {
	if err := New("http://127.0.0.1:1", nil).Ship(nil); err != nil {
		t.Fatalf("empty ship must be a no-op, got %v", err)
	}
}

// round-38: a huge backlog drains in bounded POSTs — never one request that
// outlives every client timeout.
func TestTailerBoundedBatches(t *testing.T) {
	logPath, l := tempLog(t)
	const total = 25
	for i := 0; i < total; i++ {
		if _, _, err := l.Append(receipts.Record{Task: "t", Tool: "x", Rule: "r", Decision: "approve", ArgsCanonical: "{}"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	var posts int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var p struct {
			ResourceLogs []struct {
				ScopeLogs []struct {
					LogRecords []json.RawMessage `json:"logRecords"`
				} `json:"scopeLogs"`
			} `json:"resourceLogs"`
		}
		json.Unmarshal(b, &p)
		mu.Lock()
		posts++
		got := len(p.ResourceLogs[0].ScopeLogs[0].LogRecords)
		mu.Unlock()
		if got > 10 {
			t.Errorf("batch of %d exceeds the MaxBatch cap 10", got)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	tl := &Tailer{Log: New(srv.URL, nil), LogPath: logPath, Interval: 25 * time.Millisecond,
		MaxBatch: 10, Report: func(err error) {}}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- tl.Run(stop) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done_ := posts >= 3 // 25 records / 10 cap => 3 POSTs minimum
		mu.Unlock()
		if done_ {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	p := posts
	mu.Unlock()
	if p < 3 {
		t.Fatalf("backlog never drained in bounded batches: %d posts", p)
	}
	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("tailer did not stop")
	}
}

// round-41: query-bearing endpoints — /v1/logs appends to the PATH, query
// preserved; and errors are URL-sanitized (query-string tokens never reach
// logs or output).
func TestQueryBearingEndpointAndSanitizedErrors(t *testing.T) {
	var gotPath, gotRawQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotRawQuery = r.URL.Path, r.URL.RawQuery
		w.WriteHeader(200)
	}))
	defer ts.Close()

	if err := New(ts.URL+"/ingest?token=secret-token", nil).Ship(sampleEntries()); err != nil {
		t.Fatalf("ship: %v", err)
	}
	if gotPath != "/ingest/v1/logs" {
		t.Fatalf("path append wrong: %q", gotPath)
	}
	if gotRawQuery != "token=secret-token" {
		t.Fatalf("query must be preserved: %q", gotRawQuery)
	}

	// transport failure: the error must NOT contain the token
	down := New("http://127.0.0.1:1/ingest?token=secret-token", nil)
	err := down.Ship(sampleEntries())
	if err == nil {
		t.Fatalf("transport failure expected")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("ERROR LEAKED THE QUERY-STRING TOKEN: %v", err)
	}
}

// round-41: cancellation during a backlog drain — Run returns promptly when
// stopped mid-export instead of finishing every batch.
func TestTailerStopsMidBacklog(t *testing.T) {
	logPath, l := tempLog(t)
	for i := 0; i < 30; i++ {
		if _, _, err := l.Append(receipts.Record{Task: "t", Tool: "x", Rule: "r", Decision: "approve", ArgsCanonical: "{}"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	// a slow endpoint: each POST takes ~600ms, so 3+ batches take ~2s —
	// longer than the stop deadline
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(600 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	tl := &Tailer{Log: New(srv.URL, nil), LogPath: logPath, Interval: 10 * time.Millisecond,
		MaxBatch: 5, Report: func(err error) {}}
	stop := make(chan struct{})
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- tl.Run(stop) }()

	time.Sleep(300 * time.Millisecond) // first batch in flight
	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("tailer kept draining the backlog after stop")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("shutdown took %s — cancellation did not reach the in-flight request", elapsed)
	}
}

// round-42: HTTP 200 with partialSuccess.rejectedLogRecords > 0 must be
// reported as an error — silent loss is not acceptable.
func TestPartialRejectionReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// full OTLP ack: accepted nothing of the two records
		w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":2,"errorMessage":"quota"}}`))
	}))
	defer srv.Close()
	err := New(srv.URL, nil).Ship(sampleEntries())
	if err == nil || !strings.Contains(err.Error(), "rejected 2 of 2") {
		t.Fatalf("partial rejection must be reported, got %v", err)
	}
}

// round-42: a replaced/truncated log resets the cursor — new receipts ship
// instead of being skipped by the stale count-based cursor.
func TestTailerResetsCursorOnLogReplacement(t *testing.T) {
	logPath, l := tempLog(t)
	l.Append(receipts.Record{Task: "t", Tool: "x", Rule: "r1", Decision: "approve", ArgsCanonical: "{}"})
	l.Append(receipts.Record{Task: "t", Tool: "x", Rule: "r2", Decision: "approve", ArgsCanonical: "{}"})

	rec := &bodyRecorder{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	tl := &Tailer{Log: New(srv.URL, nil), LogPath: logPath, Interval: 25 * time.Millisecond,
		Report: func(err error) {}}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- tl.Run(stop) }()

	// both original entries ship (2 records in one batch)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(rec.body(), `"stringValue":"r2"`) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(rec.body(), `"stringValue":"r2"`) {
		t.Fatalf("original entries never shipped")
	}

	// REPLACE the log with a different self-consistent chain: the count-
	// based cursor would skip everything (its history is unrelated)
	alt := filepath.Join(t.TempDir(), "alt.jsonl")
	l2, err := receipts.Open(alt, "", []byte("siem-test-key"), nil, 100)
	if err != nil {
		t.Fatalf("alt log: %v", err)
	}
	l2.Append(receipts.Record{Task: "t", Tool: "x", Rule: "replaced-a", Decision: "approve", ArgsCanonical: "{}"})
	l2.Append(receipts.Record{Task: "t", Tool: "x", Rule: "replaced-b", Decision: "deny", ArgsCanonical: "{}"})
	if _, _, err := receipts.Verify(alt, "", nil); err != nil {
		t.Fatalf("alt chain: %v", err)
	}
	if werr := copyFile(alt, logPath); werr != nil {
		t.Fatalf("replace: %v", werr)
	}

	// the tailer must reset and re-export — the new history's rules appear
	for time.Now().Before(deadline.Add(2 * time.Second)) && !strings.Contains(rec.body(), "replaced-b") {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(rec.body(), "replaced-b") {
		t.Fatalf("log replacement was not detected — new receipts skipped")
	}
	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("tailer did not stop")
	}
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}

// round-44: OTLP encodes 64-bit ints as strings sometimes — the string form
// of rejectedLogRecords must be reported too.
func TestPartialRejectionStringForm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"echo Bearer sk-leak 90f2... query token=abc"}}`))
	}))
	defer srv.Close()
	err := New(srv.URL, nil).Ship(sampleEntries())
	if err == nil || !strings.Contains(err.Error(), "rejected 1 of 2") {
		t.Fatalf("string-encoded rejection must be reported, got %v", err)
	}
	// the server-controlled message NEVER reaches the error (it can echo
	// credentials)
	for _, leak := range []string{"sk-leak", "token=abc", "quota"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("ENDPOINT MESSAGE LEAKED INTO ERROR: %q contains %q", err.Error(), leak)
		}
	}
}


// round-46: `{}` and omitted partialSuccess are VALID full success —
// rejecting them would hold the cursor and re-export forever. The server
// returns each body so the acknowledgement parsing is genuinely exercised.
func TestEmptyAckIsFullSuccess(t *testing.T) {
	for _, body := range []string{`{}`, `{"partialSuccess":{}}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(body)) // the ack under test, actually sent
		}))
		if err := New(srv.URL, nil).Ship(sampleEntries()); err != nil {
			t.Fatalf("body %s must be full success, got %v", body, err)
		}
		srv.Close()
	}
}

// round-49: redirects are rejected — a 302 must surface as an error (cursor
// held), never as a payload-less success at the destination.
func TestRedirectRejected(t *testing.T) {
	var destinationHit bool
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationHit = true
		w.WriteHeader(http.StatusOK) // empty 200 at the destination
	}))
	defer dest.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL+"/v1/logs", http.StatusFound) // 302
	}))
	defer srv.Close()

	err := New(srv.URL, nil).Ship(sampleEntries())
	if err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("redirect must surface as an error, got %v", err)
	}
	if destinationHit {
		t.Fatalf("REDIRECT FOLLOWED — the batch was silently discarded at the destination")
	}
}

// round-46: null and negative rejection counts are malformed.
func TestNullAndNegativeRejectionCountsMalformed(t *testing.T) {
	for _, body := range []string{
		`{"partialSuccess":{"rejectedLogRecords":null}}`,
		`{"partialSuccess":{"rejectedLogRecords":-3}}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(body))
		}))
		err := New(srv.URL, nil).Ship(sampleEntries())
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("body %s must be reported malformed, got %v", body, err)
		}
	}
}

// round-51: oversized acks are rejected explicitly — a silently truncated
// prefix can parse as valid JSON and accept malformed acknowledgements.
func TestOversizedAckRejected(t *testing.T) {
	junk := strings.Repeat("x", 1<<20+16) // > 1MB cap
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(junk))
	}))
	defer srv.Close()
	err := New(srv.URL, nil).Ship(sampleEntries())
	if err == nil || !strings.Contains(err.Error(), "ack exceeds") {
		t.Fatalf("oversized ack must be rejected, got %v", err)
	}
}

// round-53: multiple block IDs encode as ONE array-valued attribute —
// repeated attribute keys would lose associations (OTLP keys are unique).
func TestMultipleBlockIDsArrayValued(t *testing.T) {
	c := &bodyRecorder{}
	ts := httptest.NewServer(c.handler())
	defer ts.Close()

	entries := sampleEntries()
	entries[1].BlockIDs = []string{"b-1", "b-2", "b-3"}
	if err := New(ts.URL, nil).Ship(entries); err != nil {
		t.Fatalf("ship: %v", err)
	}

	var payload struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []struct {
					Attributes []struct {
						Key   string `json:"key"`
						Value struct {
							ArrayValue *struct {
								Values []struct {
									StringValue string `json:"stringValue"`
								} `json:"values"`
							} `json:"arrayValue"`
						} `json:"value"`
					} `json:"attributes"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal([]byte(c.body()), &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	rec := payload.ResourceLogs[0].ScopeLogs[0].LogRecords[1]
	found := false
	for _, a := range rec.Attributes {
		if a.Key == "referee.block_ids" && a.Value.ArrayValue != nil {
			found = true
			var ids []string
			for _, v := range a.Value.ArrayValue.Values {
				ids = append(ids, v.StringValue)
			}
			if strings.Join(ids, ",") != "b-1,b-2,b-3" {
				t.Fatalf("array ids wrong: %v", ids)
			}
		}
	}
	if !found {
		t.Fatalf("array-valued block_ids attribute missing")
	}
}

// round-53: a JSON-null ack body is malformed, not full success.
func TestNullAckBodyMalformed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("null"))
	}))
	defer srv.Close()
	err := New(srv.URL, nil).Ship(sampleEntries())
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("null ack body must be malformed, got %v", err)
	}
}

// round-56: NOTHING from the ack body reaches logs — not the decode error
// text (quotes raw values), not an implausible rejection count (a credential
// hidden as the count itself).
func TestAckValuesNeverReachErrors(t *testing.T) {
	for _, body := range []string{
		`{"partialSuccess":{"rejectedLogRecords":9876543210}}`,
		`{"partialSuccess":{"rejectedLogRecords":"9876543210"}}`,
		`{"partialSuccess":{"rejectedLogRecords":"not-a-number-9876543210"}}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(body))
		}))
		err := New(srv.URL, nil).Ship(sampleEntries())
		srv.Close()
		if err == nil {
			t.Fatalf("body %s must be reported", body)
		}
		if strings.Contains(err.Error(), "9876543210") {
			t.Fatalf("ENDPOINT-CONTROLLED VALUE LEAKED INTO ERROR: %v", err)
		}
	}
}

// round-66: non-200 successes (202 Accepted, 204 No Content) must NOT
// confirm delivery — OTLP success is exactly 200.
func TestNonOKStatusesNotConfirmed(t *testing.T) {
	for _, status := range []int{http.StatusAccepted, http.StatusNoContent} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		}))
		err := New(srv.URL, nil).Ship(sampleEntries())
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "cursor held") {
			t.Fatalf("status %d must hold the cursor, got %v", status, err)
		}
	}
	// 200 with a valid ack still succeeds
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	if err := New(srv.URL, nil).Ship(sampleEntries()); err != nil {
		t.Fatalf("200 with {} must succeed: %v", err)
	}
}

// round-68: partial rejection of a persistent singleton must NOT stall later
// receipts — the batch halves down to the poisoned record, it is dropped
// loudly (reported), and every good record still ships.
func TestPartialRejectionSplitsAndSkips(t *testing.T) {
	logPath, l := tempLog(t)
	rules := []string{"good-a", "good-b", "poisoned-c", "good-d"}
	for _, rule := range rules {
		if _, _, err := l.Append(receipts.Record{Task: "t", Tool: "x", Rule: rule, Decision: "approve", ArgsCanonical: "{}"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	var mu sync.Mutex
	var acceptedRules []string // rules ACCEPTED (200) — attempts don't count
	var reports []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		has := strings.Contains(string(b), "poisoned-c")
		n := strings.Count(string(b), `"referee.decision"`)
		if has {
			// reject the whole batch containing the poison; tailer splits
			w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":` + fmt.Sprint(n) + `}}`))
			return
		}
		w.WriteHeader(200)
		mu.Lock()
		for _, rule := range rules {
			if strings.Contains(string(b), `"`+rule+`"`) {
				acceptedRules = append(acceptedRules, rule)
			}
		}
		mu.Unlock()
	}))
	defer srv.Close()

	tl := &Tailer{Log: New(srv.URL, nil), LogPath: logPath, Interval: 20 * time.Millisecond,
		MaxBatch: 10, Report: func(err error) {
			mu.Lock()
			reports = append(reports, err.Error())
			mu.Unlock()
		}}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- tl.Run(stop) }()

	// every good record must ship despite the poison; the poison must be
	// dropped with a loud report
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		seen := map[string]bool{}
		for _, r := range acceptedRules {
			seen[r] = true
		}
		mu.Unlock()
		if seen["good-a"] && seen["good-b"] && seen["good-d"] {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	seen := map[string]bool{}
	for _, r := range acceptedRules {
		seen[r] = true
	}
	joinedReports := strings.Join(reports, "|")
	mu.Unlock()
	for _, good := range []string{"good-a", "good-b", "good-d"} {
		if !seen[good] {
			t.Fatalf("good record %s never shipped", good)
		}
	}
	if !strings.Contains(joinedReports, "DROPPING it") {
		t.Fatalf("poisoned record (seq 3) must be reported as dropped; reports: %s", joinedReports)
	}
	if !strings.Contains(joinedReports, "rejected (attempt 3/3)") {
		t.Fatalf("the retry budget must be exhausted before the drop; reports: %s", joinedReports)
	}

	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("tailer did not stop")
	}
}

// round-71: a singleton rejected ONCE is retried and ships when the endpoint
// recovers — temporary rejection must not become permanent loss.
func TestSingletonRejectedOnceThenAccepted(t *testing.T) {
	logPath, l := tempLog(t)
	rules := []string{"solo-retry"}
	for _, rule := range rules {
		if _, _, err := l.Append(receipts.Record{Task: "t", Tool: "x", Rule: rule, Decision: "approve", ArgsCanonical: "{}"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	var mu sync.Mutex
	var accepted []string
	var rejects int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		mu.Lock()
		rejects++
		// reject the FIRST two attempts, accept from the third on
		if rejects <= 2 {
			w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":1}}`))
			mu.Unlock()
			return
		}
		if strings.Contains(string(b), "solo-retry") {
			accepted = append(accepted, "solo-retry")
		}
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	tl := &Tailer{Log: New(srv.URL, nil), LogPath: logPath, Interval: 20 * time.Millisecond,
		MaxSingletonRetries: 5, Report: func(err error) {}}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- tl.Run(stop) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := len(accepted) > 0
		mu.Unlock()
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	acceptedLen := len(accepted)
	mu.Unlock()
	if acceptedLen == 0 {
		t.Fatalf("singleton never shipped despite retries (temporary rejection became permanent loss)")
	}

	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("tailer did not stop")
	}
}

// round-73: an accepted prefix followed by a temporarily-rejected singleton
// — the singleton's retry must wait for the NEXT tick, not burn its budget
// in the same millisecond (the round-73 bug re-POSTed immediately).
func TestHeldSingletonRetriesOnNextTick(t *testing.T) {
	logPath, l := tempLog(t)
	l.Append(receipts.Record{Task: "t", Tool: "x", Rule: "accepted-prefix", Decision: "approve", ArgsCanonical: "{}"})
	l.Append(receipts.Record{Task: "t", Tool: "x", Rule: "held-solo", Decision: "approve", ArgsCanonical: "{}"})

	var mu sync.Mutex
	var soloRejects []time.Time // attempts 1..2: rejected
	var soloAccept time.Time    // attempt 3: accepted
	soloPosts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if !strings.Contains(string(b), "held-solo") {
			w.WriteHeader(200) // the accepted prefix
			return
		}
		mu.Lock()
		soloPosts++
		n := soloPosts
		if n <= 2 {
			soloRejects = append(soloRejects, time.Now())
		} else if n == 3 {
			soloAccept = time.Now()
		}
		mu.Unlock()
		if n <= 2 {
			// reject the singleton's first two POSTs: attempt 2 happens when
			// the accepted-prefix drain re-enters shipRange within the same
			// tick (the round-73 bypass) — with the fix, attempt 3 only comes
			// on the next tick
			w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":1}}`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	tl := &Tailer{Log: New(srv.URL, nil), LogPath: logPath, Interval: 200 * time.Millisecond,
		MaxSingletonRetries: 5, Report: func(err error) {}}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- tl.Run(stop) }()

	// wait until the singleton is ACCEPTED (attempt 3, on a later tick)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := soloPosts
		mu.Unlock()
		if n >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	accept := soloAccept
	var lastReject time.Time
	if len(soloRejects) > 0 {
		lastReject = soloRejects[len(soloRejects)-1]
	}
	mu.Unlock()
	if accept.IsZero() {
		t.Fatalf("singleton never accepted (soloPosts never reached 3)")
	}
	gap := accept.Sub(lastReject)
	if gap < 100*time.Millisecond {
		close(stop)
		t.Fatalf("held singleton retried after only %s — the tick window was bypassed", gap)
	}

	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("tailer did not stop")
	}
}

// round-74: retry budgets reset when the log history is replaced — a new
// history's receipts get fresh budgets even if they reuse a seq whose old
// incarnation exhausted its retries.
func TestRetryBudgetResetsOnLogReplacement(t *testing.T) {
	logPath, l := tempLog(t)
	// the OLD singleton is always rejected — it burns its retry budget and is
	// dropped on the 3rd rejection (MaxSingletonRetries 2 → drop on #3)
	l.Append(receipts.Record{Task: "t", Tool: "x", Rule: "old-solo", Decision: "approve", ArgsCanonical: "{}"})

	var mu sync.Mutex
	var oldRejects, newRejects, newAccepts int
	phase := "old" // "old" → test flips to "new" after replacing the log
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		mu.Lock()
		defer mu.Unlock()
		if phase == "old" && strings.Contains(string(b), "old-solo") {
			oldRejects++
			// always reject the old singleton while its history is current
			w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":1}}`))
			return
		}
		if phase == "new" && strings.Contains(string(b), "new-history-solo") {
			newRejects++
			if newRejects == 1 {
				// reject the replacement ONCE: with a FRESH budget it is
				// retried and accepted; with stale seq-keyed state (already
				// exhausted by old-solo) it would be dropped on this first
				// rejection — this rejection is the discriminator
				w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":1}}`))
				return
			}
			newAccepts++
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	tl := &Tailer{Log: New(srv.URL, nil), LogPath: logPath, Interval: 20 * time.Millisecond,
		MaxSingletonRetries: 2, Report: func(err error) {}}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- tl.Run(stop) }()

	// wait for the old singleton to burn its budget: 3 rejections then dropped
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := oldRejects
		mu.Unlock()
		if n >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	if oldRejects < 3 {
		mu.Unlock()
		t.Fatalf("old singleton never burned its budget")
	}
	mu.Unlock()

	// REPLACE the log with a fresh chain: seq 1 = new-history-solo
	alt := filepath.Join(t.TempDir(), "alt.jsonl")
	l2, err := receipts.Open(alt, "", []byte("siem-test-key"), nil, 100)
	if err != nil {
		t.Fatalf("alt: %v", err)
	}
	if _, _, err := l2.Append(receipts.Record{Task: "t", Tool: "x", Rule: "new-history-solo", Decision: "approve", ArgsCanonical: "{}"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if werr := copyFile(alt, logPath); werr != nil {
		t.Fatalf("replace: %v", werr)
	}

	// flip the phase: the endpoint now rejects the NEW receipt once, accepts after
	mu.Lock()
	phase = "new"
	mu.Unlock()

	// wait for the new receipt to be rejected once, then accepted
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := newAccepts >= 1 && newRejects >= 1
		mu.Unlock()
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	rej, acc := newRejects, newAccepts
	mu.Unlock()
	if acc < 1 || rej < 1 {
		close(stop)
		t.Fatalf("new receipt must be rejected once then accepted (fresh budget proof); rejects=%d accepts=%d", rej, acc)
	}
	// THE ASSERTION: the replacement survived a rejection — with stale
	// seq-keyed retry state it would have been DROPPED on its first rejection
	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("tailer did not stop")
	}
}
func recBody(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return recText.Load().(string)
}

var recText atomic.Value // string

func init() { recText.Store("") }

// round-77: replacement while the cursor is still ZERO — the first receipt is
// mid-retry-budget when the history flips. With seq-only keys the replacement
// inherits the exhausted budget and is dropped on its first rejection; with
// hash-keyed budgets it gets fresh retries and ships.
func TestReplacementWhileCursorZero(t *testing.T) {
	logPath, l := tempLog(t)
	l.Append(receipts.Record{Task: "t", Tool: "x", Rule: "v1-solo", Decision: "approve", ArgsCanonical: "{}"})

	var mu sync.Mutex
	var v1Rejects, v2Rejects, v2Accepts int
	phase := "v1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20)) // phase decides; body unused
		mu.Lock()
		defer mu.Unlock()
		switch phase {
		case "v1":
			v1Rejects++ // always reject v1: hold at cursor 0
			w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":1}}`))
		case "v2":
			v2Rejects++
			if v2Rejects == 1 {
				// the DISCRIMINATOR rejection: fresh budget retries; stale
				// seq-keyed budget drops here
				w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":1}}`))
				return
			}
			v2Accepts++
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()

	tl := &Tailer{Log: New(srv.URL, nil), LogPath: logPath, Interval: 20 * time.Millisecond,
		MaxSingletonRetries: 1, Report: func(err error) {}}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- tl.Run(stop) }()

	// wait until v1 has been rejected once (held at cursor 0)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := v1Rejects
		mu.Unlock()
		if n >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// replace the history WHILE cursor is zero: same seq, different content
	alt := filepath.Join(t.TempDir(), "alt.jsonl")
	l2, err := receipts.Open(alt, "", []byte("siem-test-key"), nil, 100)
	if err != nil {
		t.Fatalf("alt: %v", err)
	}
	if _, _, err := l2.Append(receipts.Record{Task: "t", Tool: "x", Rule: "v2-solo", Decision: "approve", ArgsCanonical: "{}"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if werr := copyFile(alt, logPath); werr != nil {
		t.Fatalf("replace: %v", werr)
	}
	mu.Lock()
	phase = "v2"
	mu.Unlock()

	// v2 must be rejected once (fresh budget holds), then accepted
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := v2Accepts >= 1 && v2Rejects >= 1
		mu.Unlock()
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	rej, acc := v2Rejects, v2Accepts
	mu.Unlock()
	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("tailer did not stop")
	}
	if acc < 1 || rej < 1 {
		close(stop)
		t.Fatalf("replacement receipt was dropped on stale budget (rejects=%d accepts=%d)", rej, acc)
	}
}

// round-82: repeated history replacements at cursor zero must not accumulate
// retry keys — stale keys are pruned against the current log each tick.
func TestRetryKeysPrunedOnRepeatedReplacement(t *testing.T) {
	logPath, l := tempLog(t)
	l.Append(receipts.Record{Task: "t", Tool: "x", Rule: "v1", Decision: "approve", ArgsCanonical: "{}"})

	var rejectAll bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if rejectAll || strings.Contains(string(b), "stale-") {
			w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":1}}`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	tl := &Tailer{Log: New(srv.URL, nil), LogPath: logPath, Interval: 15 * time.Millisecond,
		MaxSingletonRetries: 5, Report: func(err error) {}}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- tl.Run(stop) }()

	// let v1 accumulate a retry entry
	time.Sleep(60 * time.Millisecond) // v1 accumulates a retry entry

	// replace the first receipt five times with different content — each
	// replacement orphans the previous retry key
	for i := 0; i < 5; i++ {
		alt := filepath.Join(t.TempDir(), fmt.Sprintf("alt-%d.jsonl", i))
		l2, err := receipts.Open(alt, "", []byte("siem-test-key"), nil, 100)
		if err != nil {
			t.Fatalf("alt %d: %v", i, err)
		}
		if _, _, err := l2.Append(receipts.Record{Task: "t", Tool: "x",
			Rule: fmt.Sprintf("stale-%d", i), Decision: "approve", ArgsCanonical: "{}"}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if werr := copyFile(alt, logPath); werr != nil {
			t.Fatalf("replace %d: %v", i, werr)
		}
		time.Sleep(40 * time.Millisecond) // let a tick prune
	}

	// after pruning the map holds at most the CURRENT entry's key
	if got := tl.RetryCount(); got > 1 {
		close(stop)
		t.Fatalf("STALE RETRY KEYS ACCUMULATED: %d keys — pruning failed", got)
	}

	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("tailer did not stop")
	}
}

// round-85: concurrent RetryCount readers vs releaseRetries writers — run
// with -race in CI; any unsynchronized map access panics here.
func TestRetryMapConcurrentAccess(t *testing.T) {
	logPath, l := tempLog(t)
	var recs []receipts.Record
	for i := 0; i < 20; i++ {
		recs = append(recs, receipts.Record{Task: "t", Tool: "x",
			Rule: fmt.Sprintf("rejected-%d", i), Decision: "approve", ArgsCanonical: "{}"})
	}
	for _, r := range recs {
		if _, _, err := l.Append(r); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	// each receipt is rejected ONCE, then accepted — so releaseRetries
	// cleanup genuinely runs (map populate → delete) while concurrent
	// RetryCount readers hammer the same map. Race detector catches any
	// unsynchronized access; the final assertions catch lost cleanups.
	var mu sync.Mutex
	rejectedOnce := map[string]bool{}
	var accepted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var rule string
		for _, rr := range recs {
			if strings.Contains(string(b), `"`+rr.Rule+`"`) {
				rule = rr.Rule
				break
			}
		}
		if rule == "" {
			w.WriteHeader(200)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !rejectedOnce[rule] {
			rejectedOnce[rule] = true
			w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":1}}`))
			return
		}
		accepted = append(accepted, rule)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	tl := &Tailer{Log: New(srv.URL, nil), LogPath: logPath, Interval: 5 * time.Millisecond,
		MaxBatch: 1, MaxSingletonRetries: 3, Report: func(err error) {}}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- tl.Run(stop) }()

	// concurrent reader hammering RetryCount while populate+cleanup mutate
	stopReader := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stopReader:
				return
			default:
				_ = tl.RetryCount()
			}
		}
	}()

	// wait for all 20 receipts to be accepted (each survived one rejection:
	// 20 populate→cleanup cycles under the concurrent reader)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := len(accepted) >= 20
		mu.Unlock()
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stopReader)
	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("tailer did not stop")
	}

	mu.Lock()
	acceptedN := len(accepted)
	mu.Unlock()
	if acceptedN < 20 {
		t.Fatalf("only %d of 20 receipts accepted — cleanup path under-exercised", acceptedN)
	}
	// ALL retry state must be cleaned: accepted receipts released their keys
	if got := tl.RetryCount(); got != 0 {
		t.Fatalf("retry bookkeeping not drained after acceptance: %d keys", got)
	}
}

