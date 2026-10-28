package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRecordCarriesOutcomeAndResolvedProvider(t *testing.T) {
	r := New("v1", "demo", "api", "anthropic", "", "alice", "base prompt", "base prompt + tools", 4)
	r.SetProvider("anthropic", "claude-x", "https://api.anthropic.com/v1/messages")
	r.SetBundle("bundle")
	r.AddToolCall("get_pod", `{"namespace":"demo","name":"db"}`, "ok", false, "")
	r.AddToolCall("get_pod", `{"namespace":"kube-system","name":"vault"}`, "", true, "refused")

	rec := r.Finish("db down", false, `{"summary":"db down"}`, nil)
	if rec.Outcome != "ok" || rec.Error != "" {
		t.Errorf("outcome = %q error = %q, want ok", rec.Outcome, rec.Error)
	}
	if rec.Model != "claude-x" || rec.Endpoint == "" {
		t.Errorf("resolved provider not recorded: %+v", rec)
	}
	if rec.SystemPromptSHA256 == rec.ToolSystemPromptSHA256 {
		t.Errorf("the two prompt digests must differ when the prompts differ")
	}
	if len(rec.ToolCalls) != 2 || !rec.ToolCalls[1].Refused || len(rec.Refusals) != 1 {
		t.Errorf("tool calls / refusals not recorded: %+v", rec)
	}

	failed := New("v1", "demo", "api", "anthropic", "", "alice", "p", "pt", 4).
		Finish("", false, "", errors.New("api error: 500"))
	if failed.Outcome != "error" || failed.Error != "api error: 500" {
		t.Errorf("failed run not recorded: outcome=%q error=%q", failed.Outcome, failed.Error)
	}
}

// The model is prompt-injectable: it must not be able to write unbounded text
// into the audit log through tool inputs.
func TestToolInputIsBounded(t *testing.T) {
	r := New("v1", "demo", "api", "p", "m", "u", "s", "st", 1)
	r.AddToolCall("get_pod", strings.Repeat("x", 10000), "", false, "")
	if in := r.rec.ToolCalls[0].Input; len(in) > maxInputBytes+64 || !strings.Contains(in, "truncated") {
		t.Errorf("tool input not bounded: %d bytes", len(in))
	}
}

func TestWriteJSONIsOneLine(t *testing.T) {
	var buf bytes.Buffer
	rec := New("v1", "demo", "api", "p", "m", "u", "s", "st", 1).Finish("s", false, "", nil)
	if err := WriteJSON(&buf, rec); err != nil {
		t.Fatal(err)
	}
	if strings.Count(buf.String(), "\n") != 1 || !strings.HasSuffix(buf.String(), "\n") {
		t.Errorf("not JSON Lines: %q", buf.String())
	}
	var back Record
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil || back.SchemaVersion != "2" {
		t.Errorf("round trip failed: %v %+v", err, back)
	}
}
