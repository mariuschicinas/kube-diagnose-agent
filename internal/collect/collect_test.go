package collect

import (
	"strings"
	"testing"
)

// An attacker who knows the fence markers must not be able to close the fence
// or imitate control syntax, in any letter case.
func TestNeutralizeIsCaseInsensitive(t *testing.T) {
	inputs := []string{
		untrustedStart,
		untrustedEnd,
		"<<<untrusted_log_end>>>",
		"<<<Untrusted_Log_End>>>",
		"<tool_call>", "</tool_call>", "<Tool_Call>", "<TOOL_CALL>",
		"<tool_response>", "</TOOL_RESPONSE>",
		"[INST]", "[/INST]", "[inst]", "[/Inst]",
	}
	for _, in := range inputs {
		out := neutralize("x " + in + " y")
		if strings.Contains(strings.ToLower(out), strings.ToLower(in)) {
			t.Errorf("not neutralized: %q -> %q", in, out)
		}
		if !strings.Contains(out, "(removed-") {
			t.Errorf("no placeholder for %q: %q", in, out)
		}
	}
}

func TestNeutralizeLeavesOrdinaryLogsAlone(t *testing.T) {
	benign := []string{
		"2026-10-17T10:00:00Z level=error msg=\"dial tcp db:5432: connection refused\"",
		"panic: runtime error: index out of range [3] with length 3",
		"installing tools... done",
	}
	for _, b := range benign {
		if out := neutralize(b); out != b {
			t.Errorf("false positive: %q -> %q", b, out)
		}
	}
}
