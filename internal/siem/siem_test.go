package siem

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
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
