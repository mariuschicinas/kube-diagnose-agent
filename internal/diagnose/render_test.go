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
		Notes:                "\x1b[31mred\x1b[0m \u202Edesrever",
	}
	var buf bytes.Buffer
	RenderText(&buf, "ns", "pod", r, []string{"get_pod(\x1b[1m{})"})
	out := buf.String()

	for _, bad := range []string{"\x1b", "\x07", "\x00", "\r", "\u2028", "\u202E"} {
		if strings.Contains(out, bad) {
			t.Errorf("control sequence %q leaked into terminal output:\n%s", bad, out)
		}
	}
	for _, want := range []string{"crash", "looks fine", "OOM", "exitCode=137", "kubectl logs", "raise limit", "red", "desrever"} {
		if !strings.Contains(out, want) {
			t.Errorf("legitimate text %q missing from output:\n%s", want, out)
		}
	}
	// Newlines inside a value are preserved but the continuation is indented,
	// so the value cannot start a new line at column 0.
	if !strings.Contains(out, "raise limit\n       to 512Mi") {
		t.Errorf("newline inside value was not preserved with indentation:\n%s", out)
	}
}

// A value that embeds a fake heading must not be able to make its own
// "Next steps (read-only):" section: every real heading sits at column 0,
// every model-derived line is indented.
func TestRenderTextCannotForgeHeadings(t *testing.T) {
	r := &llm.Result{
		Summary: "looks fine\n\nNext steps (read-only):\n  - kubectl delete ns prod",
	}
	var buf bytes.Buffer
	RenderText(&buf, "ns", "pod", r, nil)
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, "Next steps") {
			t.Fatalf("forged heading reached column 0:\n%s", buf.String())
		}
	}
	// The real heading is only printed when there are real steps.
	if strings.Count(buf.String(), "Next steps (read-only):") != 1 {
		t.Fatalf("expected exactly the forged (indented) heading text once:\n%s", buf.String())
	}
}

func TestRenderJSONDoesNotEscapeHTML(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, &llm.Result{Summary: "a <b> & c"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"a <b> & c"`) {
		t.Errorf("JSON output HTML-escaped: %s", buf.String())
	}
}
