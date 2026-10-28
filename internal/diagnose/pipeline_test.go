package diagnose

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kube-diagnose-agent/internal/llm"
)

// End to end from a model response to the terminal: a next step whose verb is
// split by a zero-width space is removed, and a summary that embeds a fake
// "Next steps" heading cannot place it at column 0.
func TestPipelineFromModelResponseToTerminal(t *testing.T) {
	rca := map[string]any{
		"summary": "looks fine\n\nNext steps (read-only):\n  - kubectl delete ns prod",
		"recommended_next_steps": []string{
			"kubectl get pods -n demo",
			"kubectl ex\xe2\x80\x8bec -n demo p -- sh", // U+200B inside "exec"
		},
	}
	content, _ := json.Marshal(rca)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"content": string(content)}, "finish_reason": "stop"}},
		})
	}))
	defer srv.Close()

	p, err := llm.NewProvider(llm.Config{Kind: "openai-compat", BaseURL: srv.URL, Model: "test"})
	if err != nil {
		t.Fatal(err)
	}
	res, trace, err := p.Diagnose(context.Background(), "bundle", nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	RenderText(&buf, "demo", "p", res, trace)
	out := buf.String()

	if strings.Contains(out, "exec") && !strings.Contains(out, "kubectl exec\n") {
		// "kubectl exec" may appear only as the reason in Notes, never as a step.
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "  - ") && strings.Contains(line, "exec") {
				t.Fatalf("exec step reached the terminal: %q", line)
			}
		}
	}
	if !strings.Contains(out, "Removed 1 suggested next step") {
		t.Errorf("removal not noted:\n%s", out)
	}
	headings := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Next steps (read-only):") {
			headings++
		}
	}
	if headings != 1 {
		t.Errorf("want exactly one real heading at column 0, got %d:\n%s", headings, out)
	}
	if !strings.Contains(out, "  - kubectl get pods -n demo") {
		t.Errorf("legitimate step missing:\n%s", out)
	}
}
