package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// anthServer records every request body it receives and answers from a
// per-call script.
type anthServer struct {
	t       *testing.T
	mu      sync.Mutex
	reqs    []anthReq
	replies []string // one per call, in order; the last one repeats
	status  []int    // optional per-call status (0 = 200)
}

func (s *anthServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var req anthReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.t.Errorf("bad request body: %v", err)
	}
	s.reqs = append(s.reqs, req)
	i := len(s.reqs) - 1
	if i < len(s.status) && s.status[i] != 0 {
		w.WriteHeader(s.status[i])
		_, _ = w.Write([]byte(`{"error":{"type":"overloaded_error","message":"try later"}}`))
		return
	}
	if i >= len(s.replies) {
		i = len(s.replies) - 1
	}
	w.Header().Set("content-type", "application/json")
	_, _ = w.Write([]byte(s.replies[i]))
}

func newAnthTest(t *testing.T, s *anthServer, maxIter int) (*anthropicProvider, func()) {
	t.Helper()
	s.t = t
	srv := httptest.NewServer(http.HandlerFunc(s.handler))
	return &anthropicProvider{
		httpc:     srv.Client(),
		url:       srv.URL,
		apiKey:    "test",
		model:     "test-model",
		maxTokens: 100,
		maxIter:   maxIter,
	}, srv.Close
}

const (
	anthToolUse = `{"content":[{"type":"tool_use","id":"t1","name":"get_pod","input":{"namespace":"demo","name":"db"}}],"stop_reason":"tool_use"}`
	anthFinal   = `{"content":[{"type":"text","text":"{\"summary\":\"db down\",\"likely_causes\":[]}"}],"stop_reason":"end_turn"}`
)

// Once the history contains tool_use/tool_result blocks, the API requires the
// tool definitions on every request. The forced-conclusion round must therefore
// still send `tools`, and withdraw them with tool_choice "none".
func TestAnthropicForcedRoundKeepsToolsWithToolChoiceNone(t *testing.T) {
	s := &anthServer{replies: []string{anthToolUse, anthFinal}}
	p, done := newAnthTest(t, s, 1)
	defer done()

	ft := &fakeTools{}
	res, trace, err := p.Diagnose(context.Background(), "bundle", ft)
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary != "db down" || len(trace) != 1 || ft.runs() != 1 {
		t.Fatalf("unexpected result: %+v trace=%v runs=%d", res, trace, ft.runs())
	}
	if len(s.reqs) != 2 {
		t.Fatalf("want 2 requests, got %d", len(s.reqs))
	}
	first, final := s.reqs[0], s.reqs[1]
	if len(first.Tools) == 0 || first.ToolChoice != nil {
		t.Errorf("tool round: tools offered without a tool_choice restriction expected; got tools=%d choice=%v", len(first.Tools), first.ToolChoice)
	}
	if len(final.Tools) == 0 {
		t.Errorf("forced round omitted `tools` although the history holds tool_use blocks")
	}
	if final.ToolChoice == nil || final.ToolChoice.Type != "none" {
		t.Errorf("forced round must set tool_choice none, got %v", final.ToolChoice)
	}
	if strings.Contains(final.System, "READ-ONLY tools available") {
		t.Errorf("forced round still carries the tool guidance in the system prompt")
	}
}

// A single response may carry many tool_use blocks; only the first
// maxToolCallsPerRound are executed, the rest get an error result so the model
// learns the budget.
func TestAnthropicPerRoundToolBudget(t *testing.T) {
	var blocks []string
	for i := 0; i < maxToolCallsPerRound+2; i++ {
		blocks = append(blocks, `{"type":"tool_use","id":"t`+string(rune('a'+i))+`","name":"get_pod","input":{"namespace":"demo","name":"db"}}`)
	}
	many := `{"content":[` + strings.Join(blocks, ",") + `],"stop_reason":"tool_use"}`
	s := &anthServer{replies: []string{many, anthFinal}}
	p, done := newAnthTest(t, s, 2)
	defer done()

	ft := &fakeTools{}
	if _, _, err := p.Diagnose(context.Background(), "bundle", ft); err != nil {
		t.Fatal(err)
	}
	if ft.runs() != maxToolCallsPerRound {
		t.Fatalf("executed %d tool calls, want %d", ft.runs(), maxToolCallsPerRound)
	}
	results := s.reqs[1].Messages[2].Content
	if len(results) != maxToolCallsPerRound+2 {
		t.Fatalf("every tool_use needs a tool_result, got %d", len(results))
	}
	for _, r := range results[maxToolCallsPerRound:] {
		if !r.IsError || !strings.Contains(r.Content, "per round") {
			t.Errorf("over-budget call did not get an error result: %+v", r)
		}
	}
}

func TestAnthropicMaxTokensIsAnExplicitError(t *testing.T) {
	cut := `{"content":[{"type":"text","text":"{\"summary\":\"db do"}],"stop_reason":"max_tokens"}`
	s := &anthServer{replies: []string{cut}}
	p, done := newAnthTest(t, s, 0)
	defer done()

	_, _, err := p.Diagnose(context.Background(), "bundle", nil)
	if err == nil || !strings.Contains(err.Error(), "--max-tokens") {
		t.Fatalf("want a max-tokens error, got %v", err)
	}
}

// A transient 529 in the middle of the investigation must not discard the
// whole run.
func TestAnthropicRetriesOverload(t *testing.T) {
	retryBase = 0
	defer func() { retryBase = defaultRetryBase }()

	s := &anthServer{replies: []string{anthFinal, anthFinal}, status: []int{529, 0}}
	p, done := newAnthTest(t, s, 0)
	defer done()

	res, _, err := p.Diagnose(context.Background(), "bundle", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary != "db down" || len(s.reqs) != 2 {
		t.Fatalf("expected one retry then success; got %d requests, err=%v", len(s.reqs), err)
	}
}

// Info reports what was resolved, with no secrets in the endpoint.
func TestAnthropicInfo(t *testing.T) {
	p := &anthropicProvider{url: "https://user:pw@api.example/v1/messages?key=x", model: "m"}
	info := p.Info()
	if info.Kind != "anthropic" || info.Model != "m" {
		t.Errorf("unexpected info: %+v", info)
	}
	if strings.Contains(info.Endpoint, "pw") || strings.Contains(info.Endpoint, "key=") {
		t.Errorf("endpoint leaks credentials: %q", info.Endpoint)
	}
}
