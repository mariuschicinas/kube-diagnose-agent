// Package sanitize holds the two text normalisations that sit between
// attacker-influenceable text and (a) the operator's terminal, (b) the
// read-only next-step filter. Model output is derived from container logs, so
// everything the model returns is treated as if an attacker wrote it.
//
// It is a leaf package: llm, diagnose, collect and main all import it, so it
// must import none of them.
package sanitize

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Terminal strips control characters (everything except \n and \t) so a
// string can be printed without the risk of rewriting what the operator sees:
// an ANSI escape sequence smuggled through the model must not be able to clear
// the screen, write the clipboard (OSC 52) or recolour a warning.
//
// Removed: Cc control chars (ANSI escapes, BEL, NUL, CR), the line/paragraph
// separators U+2028/U+2029, and Cf format chars — which include zero-width
// characters and the bidi overrides (U+202A-202E, U+2066-2069) used in
// "trojan source" attacks to make text display differently from what it
// contains.
func Terminal(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

// Normalize returns the canonical form of model text for the read-only
// filter: Terminal (so zero-width characters cannot split a verb), then NFKC
// (so fullwidth or otherwise decorated letters fold to ASCII — ｋubectl becomes
// kubectl), then shell line continuations joined. The filter inspects this
// form and the report prints this form, so what is checked is what is shown.
func Normalize(s string) string {
	s = Terminal(s)
	s = norm.NFKC.String(s)
	s = strings.ReplaceAll(s, "\\\n", " ")
	return s
}

// Truncate cuts s to at most n bytes on a rune boundary and appends a marker
// saying how much was dropped. Used to bound attacker-sized fields before they
// enter the bundle.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…[truncated " + itoa(len(s)-cut) + " bytes]"
}

// itoa avoids pulling strconv into a package that otherwise needs only unicode.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
