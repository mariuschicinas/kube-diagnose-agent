package llm

import (
	"fmt"
	"regexp"
	"strings"

	"kube-diagnose-agent/internal/sanitize"
)

// The read-only filter is an ALLOWLIST. Every kubectl/oc/k invocation found
// in a step must use a verb known to be read-only, or the step is dropped. A
// denylist ("block exec, delete, ...") is the wrong shape for a guarantee:
// every verb, alias, plugin or spelling it forgets is a bypass. With an
// allowlist, a verb the filter has never heard of is removed by default.
//
// Steps are normalised first (sanitize.Normalize): zero-width characters,
// fullwidth letters and line continuations are folded away, so the text the
// filter inspects is the text the operator will read.

// readOnlyVerbs are kubectl/oc verbs that only read.
var readOnlyVerbs = map[string]bool{
	"get": true, "describe": true, "logs": true, "top": true, "events": true,
	"explain": true, "api-resources": true, "api-versions": true, "version": true,
	"cluster-info": true, "wait": true,
}

// readOnlySubcommands are verbs that are read-only only with a given subcommand.
var readOnlySubcommands = map[string]map[string]bool{
	"auth":    {"can-i": true, "whoami": true},
	"rollout": {"status": true, "history": true},
	"config":  {"view": true, "get-contexts": true, "current-context": true, "get-clusters": true, "get-users": true},
}

// valueFlags are global/common flags that take their value as the NEXT token,
// so the value must not be mistaken for the verb ("kubectl -n create get pods"
// reads namespace "create").
var valueFlags = map[string]bool{
	"-n": true, "--namespace": true, "--context": true, "--kubeconfig": true,
	"--cluster": true, "--user": true, "-s": true, "--server": true, "--token": true,
	"--as": true, "--as-group": true, "--as-uid": true, "-v": true, "--v": true,
	"-l": true, "--selector": true, "-o": true, "--output": true, "-c": true,
	"--container": true, "-f": true, "--filename": true, "--field-selector": true,
	"--sort-by": true, "--request-timeout": true, "--cache-dir": true,
	"--certificate-authority": true, "--client-certificate": true, "--client-key": true,
	"--tls-server-name": true, "--profile": true, "--profile-output": true,
	"--since": true, "--since-time": true, "--tail": true, "--limit-bytes": true,
}

// proseWords follow "kubectl" in a sentence ("use kubectl to inspect ...")
// rather than in a command. Such an occurrence is not an invocation. A step
// that puts a verb after one of these words is not a runnable command either.
var proseWords = map[string]bool{
	"to": true, "for": true, "with": true, "and": true, "or": true, "command": true,
	"commands": true, "cli": true, "tool": true, "in": true, "on": true, "is": true,
	"output": true, "directly": true, "locally": true, "from": true, "via": true,
	"as": true, "the": true, "a": true, "an": true, "if": true, "that": true,
	"which": true, "against": true, "then": true, "here": true,
}

// invocationRe finds the start of a kubectl/oc invocation anywhere in a step
// (prose, backticks, after a pipe) and of the "k" alias in command position.
var invocationRe = regexp.MustCompile(
	`(?i)(?:(?:^|[\s` + "`" + `$(;|&])(kubectl|oc)|(?:^|[` + "`" + `$(;|&]\s*)(k))(?:[\s-]|$)`)

// denyPatterns catch non-kubectl ways of changing state or running code.
type denyPattern struct {
	re     *regexp.Regexp
	reason string // may contain one %s for the first submatch
}

var denyPatterns = []denyPattern{
	{regexp.MustCompile(`(?i)\bhelm\s+(?:-{1,2}[\w-]+(?:[= ]\S+)?\s+)*(install|upgrade|uninstall|delete|rollback|test)\b`), "helm %s"},
	{regexp.MustCompile(`(?i)\bcurl\b[^|;\n]*?(?:-X\s*|--request[= ]\s*)(POST|PUT|PATCH|DELETE)\b`), "curl -X %s"},
	{regexp.MustCompile(`(?i)\bcurl\b[^|;\n]*?\s(?:-d|--data(?:-\w+)?|-F|--form|-T|--upload-file)[\s=]`), "curl with a request body"},
	{regexp.MustCompile(`\|\s*(?:sudo\s+)?(sh|bash|zsh|ksh|dash)\b`), "pipe to %s"},
	{regexp.MustCompile(`(?i)\brm\s+-`), "rm -"},
	{regexp.MustCompile(`(?i)\bsystemctl\s+(restart|stop|start|reload|disable|enable)\b`), "systemctl %s"},
}

// nonReadOnlyReasons returns why step is not read-only — one entry per
// offending invocation — or nil when every command in it is a read.
func nonReadOnlyReasons(step string) []string {
	s := sanitize.Normalize(step)
	var reasons []string

	for _, loc := range invocationRe.FindAllStringSubmatchIndex(s, -1) {
		start := loc[2] // group 1: kubectl|oc
		if start < 0 {
			start = loc[4] // group 2: k
		}
		rest := s[start:]
		// One invocation ends at a shell separator or a closing backtick; the
		// next command (if any) is found by the regexp on its own.
		if i := strings.IndexAny(rest, "|;&`\n)"); i >= 0 {
			rest = rest[:i]
		}
		toks := strings.Fields(rest)
		tool := strings.ToLower(strings.TrimRight(toks[0], ".,:"))
		if i := strings.IndexByte(tool, '-'); i > 0 {
			// Plugin form (kubectl-foo): not a known read, so not allowed.
			reasons = append(reasons, tool)
			continue
		}

		verb, sub := "", ""
		for i := 1; i < len(toks); i++ {
			t := strings.ToLower(strings.Trim(toks[i], `"'`))
			if strings.HasPrefix(t, "-") {
				if valueFlags[t] {
					i++ // skip the flag's value
				}
				continue
			}
			t = strings.TrimRight(t, ".,:")
			if verb == "" {
				verb = t
				if readOnlySubcommands[verb] == nil {
					break
				}
				continue
			}
			sub = t
			break
		}

		switch {
		case verb == "", proseWords[verb]:
			// "kubectl" alone, or "kubectl to ..." in a sentence: not a command.
		case readOnlyVerbs[verb]:
		case readOnlySubcommands[verb] != nil && readOnlySubcommands[verb][sub]:
		default:
			reasons = append(reasons, strings.TrimSpace(tool+" "+verb+" "+sub))
		}
	}

	for _, d := range denyPatterns {
		if m := d.re.FindStringSubmatch(s); m != nil {
			r := d.reason
			if len(m) > 1 && strings.Contains(r, "%s") {
				r = fmt.Sprintf(r, strings.ToLower(m[1]))
			}
			reasons = append(reasons, r)
		}
	}
	return reasons
}

// enforceReadOnlySteps removes recommended next steps that are not read-only
// and records the removal in Notes. Only the reason (tool + verb) is recorded,
// never the command itself — the point is that the operator does not see it.
//
// The system prompt already forbids such steps; this is the deterministic
// backstop. A prompt rule raises the probability the model complies — real
// runs still produced `kubectl exec` suggested as "read-only" — while this
// filter guarantees the report never presents a mutating or code-executing
// command as a safe diagnostic step.
func enforceReadOnlySteps(r *Result) {
	kept := r.RecommendedNextSteps[:0]
	var removed []string
	seen := map[string]bool{}
	for _, s := range r.RecommendedNextSteps {
		reasons := nonReadOnlyReasons(s)
		if len(reasons) == 0 {
			kept = append(kept, s)
			continue
		}
		for _, why := range reasons {
			if !seen[why] {
				seen[why] = true
				removed = append(removed, why)
			}
		}
	}
	n := len(r.RecommendedNextSteps) - len(kept)
	r.RecommendedNextSteps = kept
	if n == 0 {
		return
	}
	note := fmt.Sprintf("Removed %d suggested next step(s) that were not read-only "+
		"(they would execute code in a container or change cluster state): %s",
		n, strings.Join(removed, ", "))
	r.Notes = strings.TrimSpace(note + " " + r.Notes)
}

var remoteURLRe = regexp.MustCompile(`(?i)\bhttps?://`)
var pipeToShellRe = denyPatterns[3].re

// flagRemediation marks suggested remediation items that pull in remote
// content or pipe into a shell. Remediation is shown for review, not filtered
// — but "kubectl apply -f https://..." deserves a louder label than the rest.
func flagRemediation(r *Result) {
	for i, s := range r.SuggestedRemediation {
		if remoteURLRe.MatchString(s) || pipeToShellRe.MatchString(s) {
			r.SuggestedRemediation[i] = "[!] review: contains a remote URL or pipe-to-shell — " + s
		}
	}
}
