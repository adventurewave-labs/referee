// Package siem exports the receipt log to SIEM systems over OTLP/HTTP
// (OpenTelemetry Log Records, JSON encoding per the OTLP spec — no SDK
// dependency; the only wire format Referee speaks here is stdlib net/http +
// encoding/json).
//
// Export is BEST-EFFORT by contract (PRD §6 P1): the receipt log remains the
// tamper-evident source of truth on disk; SIEM availability must never
// influence gate behavior. Failures are reported and retried on the next
// batch, never fatal to the proxy.
package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/adventurewave-labs/referee/internal/receipts"
)

// AnyValue is the OTLP AnyValue union; only the kvlistValue branch is used.
type AnyValue struct {
	KVList *KVList `json:"kvlistValue,omitempty"`
}

// KVList is an OTLP KeyValueList.
type KVList struct {
	Values []Attribute `json:"values"`
}

// Record is one OTLP log record in the JSON encoding of
// ExportLogsServiceRequest (trace/type fields omitted — Referee receipts
// carry no trace context).
type Record struct {
	TimeUnixNano string      `json:"timeUnixNano"`
	SeverityText string      `json:"severityText"`
	Body         AnyValue    `json:"body"`
	Attributes   []Attribute `json:"attributes"`
}

// Attribute is one OTLP key/value attribute.
type Attribute struct {
	Key   string  `json:"key"`
	Value anyValue `json:"value"`
}

// anyValue is the OTLP AnyValue union (JSON encoding uses the set field).
type anyValue struct {
	StringValue string `json:"stringValue,omitempty"`
}

func strAttr(k, v string) Attribute { return Attribute{Key: k, Value: anyValue{StringValue: v}} }

// severity maps a gate decision to an OTLP severity. Denials are the
// security-relevant signal: WARN. Challenges: NOTICE. Approvals: INFO.
func severity(decision string) string {
	switch decision {
	case "deny":
		return "WARN"
	case "challenge":
		return "NOTICE"
	default:
		return "INFO"
	}
}

// ToOTLP converts one receipt entry into an OTLP log record. Receipts are
// HMAC-only by design — the export never carries raw arguments (§5.4). The
// body is a valid AnyValue: a kvlistValue of string values (a bare JSON
// object is NOT a valid AnyValue encoding — round-38).
func ToOTLP(e receipts.Entry) Record {
	attrs := []Attribute{
		strAttr("referee.seq", fmt.Sprint(e.Seq)),
		strAttr("referee.task", e.Task),
		strAttr("referee.tool", e.Tool),
		strAttr("referee.rule", e.Rule),
		strAttr("referee.decision", e.Decision),
		strAttr("referee.approver", e.Approver),
		strAttr("referee.axis", e.Axis),
		strAttr("referee.args_hmac", e.ArgsHMAC),
		strAttr("referee.prev_hash", e.PrevHash),
		strAttr("referee.hash", e.Hash),
	}
	for _, id := range e.BlockIDs {
		attrs = append(attrs, strAttr("referee.block_id", id))
	}
	return Record{
		TimeUnixNano: fmt.Sprint(e.TS.UnixNano()),
		SeverityText: severity(e.Decision),
		Body: AnyValue{KVList: &KVList{Values: []Attribute{
			strAttr("event", "referee.gate_decision"),
			strAttr("decision", e.Decision),
			strAttr("tool", e.Tool),
			strAttr("rule", e.Rule),
		}}},
		Attributes: attrs,
	}
}

// Exporter ships receipt entries to an OTLP/HTTP endpoint.
type Exporter struct {
	Endpoint string            // base URL; /v1/logs is appended per OTLP
	Headers  map[string]string // auth headers etc. — from config, never secrets-in-argv
	Client   *http.Client
}

// New builds an exporter (default client timeout 10s).
func New(endpoint string, headers map[string]string) *Exporter {
	return &Exporter{Endpoint: endpoint, Headers: headers, Client: &http.Client{Timeout: 10 * time.Second}}
}

// Ship posts one batch. Returns the HTTP/API error for callers to report —
// the caller decides retry policy; Ship itself never mutates state.
//
// Endpoint handling: /v1/logs is appended to the URL PATH (query preserved)
// — string concatenation would mangle query-bearing endpoints, whose query
// strings legitimately carry SIEM tokens; every error is sanitized so no
// URL (and therefore no query-string credential) reaches logs or output
// (round-40).
func (x *Exporter) Ship(entries []receipts.Entry) error {
	return x.ShipContext(context.Background(), entries)
}

// ShipContext is Ship with a caller-owned context (cancellation stops the
// in-flight request).
func (x *Exporter) ShipContext(ctx context.Context, entries []receipts.Entry) error {
	if len(entries) == 0 {
		return nil
	}
	var records []Record
	for _, e := range entries {
		records = append(records, ToOTLP(e))
	}
	payload := map[string]any{
		"resourceLogs": []map[string]any{
			{
				"resource": map[string]any{
					"attributes": []Attribute{
						strAttr("service.name", "referee"),
					},
				},
				"scopeLogs": []map[string]any{
					{"logRecords": records},
				},
			},
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("siem: encode: %w", err)
	}
	u, err := url.Parse(x.Endpoint)
	if err != nil {
		return fmt.Errorf("siem: bad endpoint (host=%s)", sanitizedHost(x.Endpoint))
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/logs"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("siem: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range x.Headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := x.Client.Do(req)
	if err != nil {
		// sanitize: transport errors embed the full URL — query-string
		// tokens must never reach logs or output
		return fmt.Errorf("siem: post %s: %v", sanitizedHost(x.Endpoint), unwrapURL(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("siem: endpoint returned %d", resp.StatusCode)
	}
	return nil
}

// sanitizedHost reduces an endpoint to scheme://host[:port] — anything after
// the path separator (paths, queries) is dropped before it can reach a log.
func sanitizedHost(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "(unparseable-endpoint)"
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + u.Host
}

// unwrapURL strips any URL-bearing text from a transport error (net/http
// errors quote the full request URL, query string included).
func unwrapURL(err error) error {
	msg := err.Error()
	// net/http errors quote the full request URL — drop everything between
	// the first and last double quote so query-string tokens never reach
	// logs or output
	if strings.Count(msg, `"`) >= 2 {
		i := strings.Index(msg, `"`)
		j := strings.LastIndex(msg, `"`)
		msg = msg[:i] + `"<sanitized>"` + msg[j+1:]
	}
	return errors.New(msg)
}

// Tailer follows the receipt log and ships new entries as they appear.
// Position is in-memory: a restart re-exports from the beginning — SIEM
// pipelines dedupe on referee.seq (documented; the alternative, a state
// file, is v2). Failures log and continue: the log on disk stays the source
// of truth.
type Tailer struct {
	Log      *Exporter
	LogPath  string
	Interval time.Duration
	Report   func(err error) // failure reporter (logger); nil = silent
	// MaxBatch caps records per POST (default 500): a huge backlog must
	// drain in many bounded POSTs, never one request that outlives every
	// client timeout and stalls export forever (round-38).
	MaxBatch int
}

// Run blocks, shipping batches of new entries every Interval. It never
// returns on transient log/endpoint errors (best-effort contract): only the
// stop signal ends it.
func (t *Tailer) Run(stop <-chan struct{}) error {
	if t.Interval <= 0 {
		t.Interval = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	shipped := 0 // in-memory cursor: number of entries already exported
	tick := time.NewTicker(t.Interval)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return nil
		case <-tick.C:
			entries, err := receipts.ReadAll(t.LogPath)
			if err != nil {
				if os.IsNotExist(err) {
					continue // log not created yet
				}
				// transient read error (rotation, fs hiccup): report and
				// retry next tick — the tailer is best-effort by contract
				// and never goes permanently dark on a hiccup (round-39)
				if t.Report != nil {
					t.Report(fmt.Errorf("siem: log read: %w", err))
				}
				continue
			}
			if len(entries) <= shipped {
				continue
			}
			max := t.MaxBatch
			if max <= 0 {
				max = 500
			}
			for shipped < len(entries) { // bounded chunks until caught up
				select {
				case <-stop:
					return nil // cancellation works mid-backlog (round-40)
				default:
				}
				end := shipped + max
				if end > len(entries) {
					end = len(entries)
				}
				if err := t.Log.ShipContext(ctx, entries[shipped:end]); err != nil {
					if t.Report != nil {
						t.Report(err)
					}
					break // retry the same cursor next tick (best-effort)
				}
				shipped = end
			}
		}
	}
}
