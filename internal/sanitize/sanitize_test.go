package sanitize

import (
	"strings"
	"testing"
)

func TestTerminalStripsControlAndFormatCharacters(t *testing.T) {
	in := "crash\x1b[2J\x1b[H looks\x07 fine\x00\r\n\u2028\u202ERTL\u200bzw\tTAB"
	out := Terminal(in)
	for _, bad := range []string{"\x1b", "\x07", "\x00", "\r", "\u2028", "\u202E", "\u200b"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q survived Terminal(): %q", bad, out)
		}
	}
	if out != "crash[2J[H looks fine\nRTLzw\tTAB" {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestNormalizeFoldsEvasions(t *testing.T) {
	cases := map[string]string{
		"kubectl ex\u200bec -n demo api -- sh": "kubectl exec -n demo api -- sh", // zero-width space
		"kubectl ex\u00adec":                   "kubectl exec",                   // soft hyphen
		"ｋｕｂｅｃｔｌ exec":                         "kubectl exec",                   // fullwidth
		"kubectl \\\n  exec pod":               "kubectl    exec pod",            // line continuation
		"kubectl \u202Eexec":                   "kubectl exec",                   // bidi override
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := Truncate("short", 10); got != "short" {
		t.Errorf("short string changed: %q", got)
	}
	got := Truncate(strings.Repeat("a", 100), 10)
	if !strings.HasPrefix(got, "aaaaaaaaaa…[truncated 90 bytes]") {
		t.Errorf("unexpected truncation: %q", got)
	}
	// Never cut inside a multi-byte rune.
	got = Truncate("ééééé", 3) // each é is 2 bytes
	if !strings.HasPrefix(got, "é…") {
		t.Errorf("cut inside a rune: %q", got)
	}
}
