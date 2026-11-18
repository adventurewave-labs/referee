package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// NewHTTPJudge builds a judge from policy judge config. Provider:
//   - openai:    OpenAI-compatible /chat/completions (endpoint may point at
//     any compatible deployment)
//   - anthropic: Anthropic /v1/messages
//   - mock:      scripted verdicts (tests/demo only)
//
// API keys travel via the environment variable named by apiKeyEnv — never in
// argv, logs, or git.
func NewHTTPJudge(provider, model, endpoint, apiKeyEnv string) (Judge, error) {
	switch provider {
	case "mock":
		return &MockJudge{}, nil
	case "openai", "anthropic":
		return &HTTPJudge{Provider: provider, Model: model, Endpoint: strings.TrimRight(endpoint, "/"), APIKeyEnv: apiKeyEnv, client: &http.Client{Timeout: 30 * time.Second}}, nil
	}
	return nil, fmt.Errorf("probe: unknown judge provider %q (openai|anthropic|mock)", provider)
}

// HTTPJudge is the production judge over an LLM HTTP API.
type HTTPJudge struct {
	Provider  string
	Model     string
	Endpoint  string
	APIKeyEnv string
	client    *http.Client
}

func (h *HTTPJudge) Judge(ctx context.Context, req Request) (Verdict, error) {
	system, user := BuildPrompt(req)
	var (
		url  string
		hdr  map[string]string
		body []byte
	)
	switch h.Provider {
	case "openai":
		url = h.Endpoint + "/chat/completions"
		hdr = map[string]string{"Authorization": "Bearer " + h.apiKey()}
		body = mustJSON(map[string]any{
			"model": h.Model,
			"messages": []map[string]string{
				{"role": "system", "content": system},
				{"role": "user", "content": user},
			},
			"temperature":     0,
			"response_format": map[string]string{"type": "json_object"},
		})
	case "anthropic":
		url = h.Endpoint + "/v1/messages"
		hdr = map[string]string{"x-api-key": h.apiKey(), "anthropic-version": "2023-06-01"}
		body = mustJSON(map[string]any{
			"model":      h.Model,
			"max_tokens": 256,
			"system":     system,
			"messages":   []map[string]string{{"role": "user", "content": user}},
		})
	default:
		return Verdict{}, fmt.Errorf("probe: unknown provider %q", h.Provider)
	}

	reqW, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Verdict{}, err
	}
	reqW.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		if v != "" {
			reqW.Header.Set(k, v)
		}
	}
	resp, err := h.client.Do(reqW)
	if err != nil {
		return Verdict{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Verdict{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Verdict{}, fmt.Errorf("probe: judge http %d", resp.StatusCode)
	}
	var text string
	switch h.Provider {
	case "openai":
		var out struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(b, &out); err != nil || len(out.Choices) == 0 {
			return Verdict{}, fmt.Errorf("probe: bad openai judge response")
		}
		text = out.Choices[0].Message.Content
	case "anthropic":
		var out struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(b, &out); err != nil {
			return Verdict{}, fmt.Errorf("probe: bad anthropic judge response")
		}
		for _, c := range out.Content {
			if c.Type == "text" {
				text = c.Text
			}
		}
		if text == "" {
			return Verdict{}, fmt.Errorf("probe: anthropic judge returned no text")
		}
	}
	return ParseVerdict(text)
}

func (h *HTTPJudge) apiKey() string {
	if h.APIKeyEnv == "" {
		return ""
	}
	return os.Getenv(h.APIKeyEnv)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // config-shaped data; marshal cannot fail here
	}
	return b
}

// MockJudge returns deterministic verdicts for tests, the demo, and the
// tuning harness. Two marker sets:
//   - TaintWhen: taint when the ARGUMENT contains the marker (casefold) —
//     models a judge keyed on argument content;
//   - BlockTaintWhen: taint when any UNTRUSTED BLOCK in the set contains the
//     marker — models a judge that spots the injected instruction in the
//     set (the set-based question's happy path).
type MockJudge struct {
	TaintWhen      []string
	BlockTaintWhen []string
}

func (m *MockJudge) Judge(_ context.Context, req Request) (Verdict, error) {
	for _, t := range m.BlockTaintWhen {
		tl := strings.ToLower(t)
		for _, b := range req.Untrusted {
			if strings.Contains(strings.ToLower(b.Text), tl) {
				return Verdict{Verdict: Tainted, Confidence: 0.95}, nil
			}
		}
	}
	low := strings.ToLower(req.Argument)
	for _, t := range m.TaintWhen {
		if strings.Contains(low, strings.ToLower(t)) {
			return Verdict{Verdict: Tainted, Confidence: 0.95}, nil
		}
	}
	return Verdict{Verdict: Clean, Confidence: 0.9}, nil
}
