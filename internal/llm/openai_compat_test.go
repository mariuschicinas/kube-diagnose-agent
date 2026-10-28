package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeTools records every execution so tests can assert what ran, with what
// input, and that refused rounds ran nothing.
type fakeTools struct {
	mu    sync.Mutex
	calls []struct{ name, input string }
	fail  error // returned by Run when non-nil
}

func (f *fakeTools) Defs() []ToolDef {
	return []ToolDef{{Name: "get_pod", Description: "test", InputSchema: json.RawMessage(`{"type":"object"}`)}}
}

func (f *fakeTools) Run(ctx context.Context, name string, input json.RawMessage) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, struct{ name, input string }{name, string(input)})
	if f.fail != nil {
		return "", f.fail
	}
	return "ok", nil
}

func (f *fakeTools) runs() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// oaiServer records request bodies and answers from a per-call script (the
// last reply repeats).
type oaiServer struct {
	mu      sync.Mutex
	reqs    []oaiReq
	replies []string
	status  []int
}

func (s *oaiServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var req oaiReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.reqs = append(s.reqs, req)
	i := len(s.reqs) - 1
	if i < len(s.status) && s.status[i] != 0 {
		w.WriteHeader(s.status[i])
		_, _ = w.Write([]byte(`{"error":{"type":"server_error","message":"boom"}}`))
		return
	}
	if i >= len(s.replies) {
		i = len(s.replies) - 1
	}
	w.Header().Set("content-type", "application/json")
	_, _ = w.Write([]byte(s.replies[i]))
}

const (
	oaiToolCallReply = `{"choices":[{"message":{"content":"","tool_calls":[
		{"id":"c1","type":"function","function":{"name":"get_pod","arguments":"{\"namespace\":\"demo\",\"name\":\"x\"}"}}
	]}}]}`
	oaiFinalReply = `{"choices":[{"message":{"content":"{\"summary\":\"db missing\",\"likely_causes\":[]}"},"finish_reason":"stop"}]}`
)

// alwaysToolCalls is the behaviour of a weak self-hosted model: it answers
// with a tool call regardless of whether tools were offered.
func alwaysToolCalls(t *testing.T) *httptest.Server {
	t.Helper()
	s := &oaiServer{replies: []string{oaiToolCallReply}}
	return httptest.NewServer(http.HandlerFunc(s.handler))
}

func newTestProvider(t *testing.T, base string, maxIter int) Provider {
	t.Helper()
	p, err := newOpenAICompat(Config{BaseURL: base, Model: "test", MaxIterations: maxIter})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// With --max-iterations 0 there is no tool provider. A backend that returns
// tool calls anyway must produce an error, not a nil-pointer panic.
func TestUnofferedToolCallsWithNoProviderDoNotPanic(t *testing.T) {
	srv := alwaysToolCalls(t)
	defer srv.Close()

	_, _, err := newTestProvider(t, srv.URL, 0).Diagnose(context.Background(), "bundle", nil)
	if err == nil || !strings.Contains(err.Error(), "none were offered") {
		t.Fatalf("want 'none were offered' error, got %v", err)
	}
}

// Tools offered for maxIter rounds only. In the forced-conclusion round the
// model is not offered tools; if it calls one anyway, the call must be refused
// and NOT executed.
func TestToolCallsOnlyExecutedWhenOffered(t *testing.T) {
	srv := alwaysToolCalls(t)
	defer srv.Close()

	ft := &fakeTools{}
	_, _, err := newTestProvider(t, srv.URL, 1).Diagnose(context.Background(), "bundle", ft)
	if err == nil || !strings.Contains(err.Error(), "none were offered") {
		t.Fatalf("want 'none were offered' error, got %v", err)
	}
	if ft.runs() != 1 {
		t.Fatalf("tool executed %d times, want exactly 1 (the offered round)", ft.runs())
	}
}

// The wire shape this API requires: the assistant's tool-call turn echoed
// back, then one tool message per call carrying the same tool_call_id; a tool
// error is fed back as content so the model can correct itself. The tool
// receives exactly the arguments the model sent.
func TestOpenAICompatEchoesToolCallIDsAndFeedsBackErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail error
		want string
	}{
		{"success", nil, "ok"},
		{"tool_error", errors.New("refused: wrong namespace"), "tool error: refused: wrong namespace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &oaiServer{replies: []string{oaiToolCallReply, oaiFinalReply}}
			srv := httptest.NewServer(http.HandlerFunc(s.handler))
			defer srv.Close()

			ft := &fakeTools{fail: tc.fail}
			res, trace, err := newTestProvider(t, srv.URL, 2).Diagnose(context.Background(), "bundle", ft)
			if err != nil || res.Summary != "db missing" {
				t.Fatalf("res=%+v err=%v", res, err)
			}
			if len(ft.calls) != 1 || ft.calls[0].name != "get_pod" || ft.calls[0].input != `{"namespace":"demo","name":"x"}` {
				t.Fatalf("tool did not receive the model's arguments: %+v", ft.calls)
			}
			if len(trace) != 1 || !strings.HasPrefix(trace[0], "get_pod(") {
				t.Fatalf("trace = %v", trace)
			}
			if len(s.reqs) != 2 {
				t.Fatalf("want 2 requests, got %d", len(s.reqs))
			}
			msgs := s.reqs[1].Messages
			// system, user, assistant(tool_calls), tool
			if len(msgs) != 4 || msgs[2].Role != "assistant" || len(msgs[2].ToolCls) != 1 || msgs[2].ToolCls[0].ID != "c1" {
				t.Fatalf("assistant tool-call turn not echoed: %+v", msgs)
			}
			if msgs[3].Role != "tool" || msgs[3].ToolCallID != "c1" || msgs[3].Content != tc.want {
				t.Fatalf("tool result turn wrong: %+v", msgs[3])
			}
			if len(s.reqs[0].Tools) != 1 {
				t.Errorf("tools not offered in round 0")
			}
			if len(s.reqs[1].Tools) != 1 {
				t.Errorf("tools not offered in round 1 of 2")
			}
		})
	}
}

// The round count is honoured exactly: maxIter tool rounds, then one forced
// conclusion without tools.
func TestOpenAICompatRoundBudget(t *testing.T) {
	s := &oaiServer{replies: []string{oaiToolCallReply, oaiToolCallReply, oaiToolCallReply, oaiToolCallReply, oaiFinalReply}}
	srv := httptest.NewServer(http.HandlerFunc(s.handler))
	defer srv.Close()

	ft := &fakeTools{}
	res, _, err := newTestProvider(t, srv.URL, 4).Diagnose(context.Background(), "bundle", ft)
	if err != nil || res == nil {
		t.Fatalf("err=%v", err)
	}
	if ft.runs() != 4 || len(s.reqs) != 5 {
		t.Fatalf("runs=%d requests=%d, want 4 and 5", ft.runs(), len(s.reqs))
	}
	if len(s.reqs[4].Tools) != 0 || strings.Contains(s.reqs[4].Messages[0].Content, "READ-ONLY tools available") {
		t.Errorf("forced-conclusion round still offered tools")
	}
}

func TestOpenAICompatBackendErrors(t *testing.T) {
	retryBase = 0
	defer func() { retryBase = defaultRetryBase }()

	cases := map[string]struct {
		s    *oaiServer
		want string
	}{
		"no_choices":     {&oaiServer{replies: []string{`{"choices":[]}`}}, "no choices"},
		"error_body":     {&oaiServer{replies: []string{oaiFinalReply}, status: []int{400}}, "backend error"},
		"persistent_5xx": {&oaiServer{replies: []string{oaiFinalReply}, status: []int{503, 503, 503}}, "backend error"},
		"length":         {&oaiServer{replies: []string{`{"choices":[{"message":{"content":"{\"summary\":\"db mis"},"finish_reason":"length"}]}`}}, "--max-tokens"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(tc.s.handler))
			defer srv.Close()
			_, _, err := newTestProvider(t, srv.URL, 0).Diagnose(context.Background(), "bundle", nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
	// A transient failure is retried, then the run succeeds.
	s := &oaiServer{replies: []string{oaiFinalReply, oaiFinalReply}, status: []int{503, 0}}
	srv := httptest.NewServer(http.HandlerFunc(s.handler))
	defer srv.Close()
	res, _, err := newTestProvider(t, srv.URL, 0).Diagnose(context.Background(), "bundle", nil)
	if err != nil || res.Summary != "db missing" || len(s.reqs) != 2 {
		t.Fatalf("retry did not recover: err=%v requests=%d", err, len(s.reqs))
	}
}

// An --api-key-env naming an unset variable is a typo, not "no auth".
func TestOpenAICompatRejectsEmptyAPIKeyEnv(t *testing.T) {
	t.Setenv("KDA_TEST_EMPTY_KEY", "")
	_, err := newOpenAICompat(Config{BaseURL: "http://localhost:1/v1", APIKeyEnv: "KDA_TEST_EMPTY_KEY"})
	if err == nil || !strings.Contains(err.Error(), "KDA_TEST_EMPTY_KEY") {
		t.Fatalf("want an error naming the variable, got %v", err)
	}
}

// Errors must show the endpoint without credentials or query parameters.
func TestOpenAICompatErrorsRedactTheURL(t *testing.T) {
	retryBase = 0
	defer func() { retryBase = defaultRetryBase }()
	t.Setenv("KDA_TEST_KEY", "k")
	p, err := newOpenAICompat(Config{BaseURL: "http://user:pw@127.0.0.1:1/v1?token=zzz", APIKeyEnv: "KDA_TEST_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = p.Diagnose(context.Background(), "bundle", nil)
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if strings.Contains(err.Error(), "pw") || strings.Contains(err.Error(), "zzz") {
		t.Fatalf("error leaks credentials: %v", err)
	}
	if info := p.Info(); strings.Contains(info.Endpoint, "pw") || strings.Contains(info.Endpoint, "zzz") {
		t.Fatalf("info leaks credentials: %+v", info)
	}
}

// A well-behaved backend that answers with the final JSON returns a result.
func TestFinalAnswerIsParsed(t *testing.T) {
	s := &oaiServer{replies: []string{oaiFinalReply}}
	srv := httptest.NewServer(http.HandlerFunc(s.handler))
	defer srv.Close()

	res, _, err := newTestProvider(t, srv.URL, 4).Diagnose(context.Background(), "bundle", &fakeTools{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary != "db missing" {
		t.Fatalf("summary = %q", res.Summary)
	}
}
