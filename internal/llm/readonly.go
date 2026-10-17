package llm

import (
	"fmt"
	"regexp"
	"strings"
)

// nonReadOnlyCmd matches a kubectl/oc invocation whose verb is not a read:
// commands that run code inside a container (exec, attach, debug, cp,
// port-forward, run) or that change cluster state. Global flags may precede the
// verb ("kubectl -n demo exec ..."); the optional flag group handles that.
var nonReadOnlyCmd = regexp.MustCompile(
	`(?i)\b(?:kubectl|oc)` +
		`(?:\s+-{1,2}[\w-]+(?:[= ]\S+)?)*` + // global flags, e.g. -n demo, --context=x
		`\s+(?:` +
		`exec|attach|debug|cp|port-forward|proxy|run|` +
		`apply|create|replace|patch|edit|delete|scale|autoscale|set|label|annotate|` +
		`expose|taint|drain|cordon|uncordon|` +
		`rollout\s+(?:restart|undo|pause|resume)` +
		`)\b`)

// enforceReadOnlySteps removes recommended next steps that are not read-only
// and records the removal in Notes.
//
// The system prompt already forbids such steps; this is the deterministic
// backstop. A prompt rule raises the probability the model complies — real
// runs still produced `kubectl exec` suggested as "read-only" — while this
// filter guarantees the report never presents a mutating or code-executing
// command as a safe diagnostic step.
func enforceReadOnlySteps(r *Result) {
	kept := r.RecommendedNextSteps[:0]
	var removed []string
	for _, s := range r.RecommendedNextSteps {
		if nonReadOnlyCmd.MatchString(s) {
			removed = append(removed, s)
			continue
		}
		kept = append(kept, s)
	}
	r.RecommendedNextSteps = kept
	if len(removed) == 0 {
		return
	}
	note := fmt.Sprintf("Removed %d suggested next step(s) that were not read-only "+
		"(they would execute code in a container or change cluster state): %s",
		len(removed), strings.Join(removed, " | "))
	r.Notes = strings.TrimSpace(note + " " + r.Notes)
}
