package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeTools counts executions so tests can assert a tool was NOT run.
type fakeTools struct{ runs int }

func (f *fakeTools) Defs() []ToolDef {
	return []ToolDef{{Name: "get_pod", Description: "test", InputSchema: json.RawMessage(`{"type":"object"}`)}}
}

func (f *fakeTools) Run(ctx context.Context, name string, input json.RawMessage) (string, error) {
	f.runs++
	return "ok", nil
}

// backend returns an OpenAI-compatible server that always answers with a tool
// call, regardless of whether tools were offered — the behaviour of a weak
// self-hosted model.
func alwaysToolCalls(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"","tool_calls":[
			{"id":"c1","type":"function","function":{"name":"get_pod","arguments":"{\"namespace\":\"demo\",\"name\":\"x\"}"}}
		]}}]}`))
	}))
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
	if ft.runs != 1 {
		t.Fatalf("tool executed %d times, want exactly 1 (the offered round)", ft.runs)
	}
}

// A truncated answer must say so, not surface as a cryptic parse error.
func TestOpenAICompatLengthFinishIsAnExplicitError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"summary\":\"db mis"},"finish_reason":"length"}]}`))
	}))
	defer srv.Close()

	_, _, err := newTestProvider(t, srv.URL, 0).Diagnose(context.Background(), "bundle", nil)
	if err == nil || !strings.Contains(err.Error(), "--max-tokens") {
		t.Fatalf("want a max-tokens error, got %v", err)
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"summary\":\"db missing\",\"likely_causes\":[]}"}}]}`))
	}))
	defer srv.Close()

	res, _, err := newTestProvider(t, srv.URL, 4).Diagnose(context.Background(), "bundle", &fakeTools{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary != "db missing" {
		t.Fatalf("summary = %q", res.Summary)
	}
}
