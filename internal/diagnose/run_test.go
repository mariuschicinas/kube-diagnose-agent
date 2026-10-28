package diagnose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"kube-diagnose-agent/internal/audit"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// backend is an OpenAI-compatible stub: on its first call it asks for a Pod
// in kube-system (what a prompt-injected model does), then answers.
func backend(t *testing.T) *httptest.Server {
	t.Helper()
	var calls atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"","tool_calls":[
				{"id":"c1","type":"function","function":{"name":"get_pod","arguments":"{\"namespace\":\"kube-system\",\"name\":\"vault-0\"}"}},
				{"id":"c2","type":"function","function":{"name":"get_service","arguments":"{\"namespace\":\"demo\",\"name\":\"db\"}"}}
			]}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"summary\":\"db Service missing\",\"likely_causes\":[{\"cause\":\"no db Service\",\"confidence\":\"high\",\"evidence\":[\"get_service NOT FOUND\"]}]}"},"finish_reason":"stop"}]}`))
	}))
}

func demoPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "demo", UID: "u1"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "busybox"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
			Name: "app", RestartCount: 4,
			LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, Message: "DB_PASSWORD=hunter2secret"}},
		}}},
	}
}

// The whole pipeline against a fake cluster and a stub model: the
// cross-namespace read is refused in code and surfaced, the in-namespace
// read runs, the bundle is redacted, and the audit record describes the run.
func TestRunEndToEnd(t *testing.T) {
	srv := backend(t)
	defer srv.Close()
	cs := fake.NewClientset(demoPod(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "vault-0", Namespace: "kube-system"}})

	var auditBuf bytes.Buffer
	rep, err := Run(context.Background(), cs, Options{
		Namespace: "demo", Pod: "api",
		Provider: "openai-compat", BaseURL: srv.URL, Model: "stub", MaxIterations: 2,
		AgentVersion: "test", Initiator: "tester", AuditWriter: &auditBuf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Result == nil || rep.Result.Summary != "db Service missing" {
		t.Fatalf("unexpected result: %+v", rep.Result)
	}
	if len(rep.Denied) != 1 || !strings.Contains(rep.Denied[0], "kube-system") {
		t.Fatalf("cross-namespace call not reported as denied: %v", rep.Denied)
	}
	if !strings.HasPrefix(rep.Result.Notes, "SECURITY:") || !strings.Contains(rep.Result.Notes, "kube-system") {
		t.Fatalf("SECURITY warning missing from notes: %q", rep.Result.Notes)
	}
	// The trace shows what the agent attempted, refused calls included: an
	// operator reading the report must see the kube-system attempt.
	if len(rep.Trace) != 2 || !strings.HasPrefix(rep.Trace[0], "get_pod(") || !strings.HasPrefix(rep.Trace[1], "get_service(") {
		t.Fatalf("trace should list both attempts in order: %v", rep.Trace)
	}
	for _, a := range cs.Actions() {
		if a.GetNamespace() == "kube-system" {
			t.Fatalf("a kube-system read reached the API server: %v", a)
		}
	}
	if strings.Contains(rep.Bundle, "hunter2secret") || !strings.Contains(rep.Bundle, "[REDACTED]") {
		t.Errorf("bundle not redacted:\n%s", rep.Bundle)
	}
	if rep.AuditErr != nil {
		t.Fatalf("audit error: %v", rep.AuditErr)
	}

	var rec audit.Record
	if err := json.Unmarshal(auditBuf.Bytes(), &rec); err != nil {
		t.Fatalf("audit record is not one JSON object: %v\n%s", err, auditBuf.String())
	}
	if rec.Outcome != "ok" || rec.Model != "stub" || rec.Provider != "openai-compat" || !strings.HasPrefix(rec.Endpoint, srv.URL) {
		t.Errorf("audit record does not describe the run: %+v", rec)
	}
	if len(rec.ToolCalls) != 2 || !rec.ToolCalls[0].Refused || rec.ToolCalls[1].Refused || len(rec.Refusals) != 1 {
		t.Errorf("audit tool calls wrong: %+v", rec.ToolCalls)
	}
	if rec.BundleSHA256 == "" || rec.ResultSHA256 == "" || rec.SystemPromptSHA256 == rec.ToolSystemPromptSHA256 {
		t.Errorf("audit digests missing: %+v", rec)
	}
}

// A run that fails before the model is called still leaves an audit record
// that says so.
func TestRunAuditsFailures(t *testing.T) {
	var auditBuf bytes.Buffer
	rep, err := Run(context.Background(), fake.NewClientset(), Options{
		Namespace: "demo", Pod: "missing", Provider: "openai-compat", BaseURL: "http://127.0.0.1:1/v1",
		AuditWriter: &auditBuf,
	})
	if err == nil {
		t.Fatal("expected an error for a missing pod")
	}
	if rep == nil || rep.Bundle != "" || rep.AuditErr != nil {
		t.Fatalf("report after failure: %+v", rep)
	}
	var rec audit.Record
	if jerr := json.Unmarshal(auditBuf.Bytes(), &rec); jerr != nil {
		t.Fatalf("no audit record for a failed run: %v", jerr)
	}
	if rec.Outcome != "error" || !strings.Contains(rec.Error, "missing") {
		t.Errorf("failure not recorded: %+v", rec)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// An audit write failure is reported, not swallowed, and does not fail the
// diagnosis itself.
func TestRunReportsAuditWriteErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"summary\":\"fine\"}"}}]}`))
	}))
	defer srv.Close()
	rep, err := Run(context.Background(), fake.NewClientset(demoPod()), Options{
		Namespace: "demo", Pod: "api", Provider: "openai-compat", BaseURL: srv.URL,
		AuditWriter: failingWriter{},
	})
	if err != nil || rep.Result == nil {
		t.Fatalf("diagnosis failed because of the audit writer: %v", err)
	}
	if rep.AuditErr == nil || !strings.Contains(rep.AuditErr.Error(), "disk full") {
		t.Fatalf("audit write error not reported: %v", rep.AuditErr)
	}
}
