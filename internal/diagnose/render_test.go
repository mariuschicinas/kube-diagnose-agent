package diagnose

import (
	"bytes"
	"strings"
	"testing"

	"kube-diagnose-agent/internal/llm"
)

// Model output is derived from attacker-influenceable logs. Terminal escape
// sequences must never reach the operator's terminal.
func TestRenderTextStripsControlCharacters(t *testing.T) {
	r := &llm.Result{
		Summary: "crash\x1b[2J\x1b[H looks fine\x07",
		LikelyCauses: []llm.Cause{{
			Cause:      "OOM\x1b]0;pwned\x07",
			Confidence: "high",
			Evidence:   []string{"exit\u2028Code=137"},
		}},
		RecommendedNextSteps: []string{"kubectl logs\x00"},
		SuggestedRemediation: []string{"raise limit\r\n to 512Mi"},
		Notes:                "\x1b[31mred\x1b[0m \u202edesrever",
	}
	var buf bytes.Buffer
	RenderText(&buf, "ns", "pod", r, []string{"get_pod(\x1b[1m{})"})
	out := buf.String()

	for _, bad := range []string{"\x1b", "\x07", "\x00", "\r", "\u2028", "\u202e"} {
		if strings.Contains(out, bad) {
			t.Errorf("control sequence %q leaked into terminal output:\n%s", bad, out)
		}
	}
	for _, want := range []string{"crash", "looks fine", "OOM", "exitCode=137", "kubectl logs", "raise limit", "red", "desrever"} {
		if !strings.Contains(out, want) {
			t.Errorf("legitimate text %q missing from output:\n%s", want, out)
		}
	}
	// Newlines inside a value are preserved (they are harmless and readable).
	if !strings.Contains(out, "raise limit\n to 512Mi") {
		t.Errorf("newline inside value was not preserved:\n%s", out)
	}
}
