// Package diagnose wires the pipeline together: gather a read-only bundle,
// redact it, then run the LLM tool-use loop that may investigate with read-only
// tools before producing the RCA.
package diagnose

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"

	"kube-diagnose-agent/internal/audit"
	"kube-diagnose-agent/internal/collect"
	"kube-diagnose-agent/internal/llm"
	"kube-diagnose-agent/internal/redact"
	"kube-diagnose-agent/internal/tools"

	"k8s.io/client-go/kubernetes"
)

// Options controls a single diagnose run.
type Options struct {
	Namespace string
	Pod       string
	Tail      int64

	// LLM backend selection. Provider is "anthropic" or "openai-compat";
	// BaseURL/APIKeyEnv apply to openai-compat (Ollama, vLLM, LiteLLM, OpenAI).
	Provider      string
	Model         string
	BaseURL       string
	APIKeyEnv     string
	MaxTokens     int
	MaxIterations int

	// Audit. AgentVersion and Initiator are stamped into the record. AuditWriter,
	// if non-nil, receives one JSON-Lines audit record for the run.
	AgentVersion string
	Initiator    string
	AuditWriter  io.Writer
}

// Run executes the full pipeline. It returns the structured result, the redacted
// initial bundle (so callers can show exactly what left the cluster), and a
// trace of the tool calls the agent made during investigation.
func Run(ctx context.Context, cs kubernetes.Interface, o Options) (*llm.Result, string, []string, error) {
	bundle, err := collect.New(cs, o.Tail).Gather(ctx, o.Namespace, o.Pod)
	if err != nil {
		return nil, "", nil, err
	}

	clean := redact.Scrub(bundle.Text)

	client, err := llm.NewProvider(llm.Config{
		Kind:          o.Provider,
		Model:         o.Model,
		BaseURL:       o.BaseURL,
		APIKeyEnv:     o.APIKeyEnv,
		MaxTokens:     o.MaxTokens,
		MaxIterations: o.MaxIterations,
	})
	if err != nil {
		return nil, clean, nil, err
	}

	rec := audit.New(o.AgentVersion, o.Namespace, o.Pod, o.Provider, o.Model,
		o.Initiator, llm.SystemPrompt(), o.MaxIterations)
	rec.SetBundle(clean)

	var provider llm.ToolProvider
	var tp *tools.Provider
	if o.MaxIterations > 0 {
		// The provider is locked to the target Pod's namespace: reads elsewhere
		// are refused in code, regardless of what the model is talked into.
		tp = tools.New(cs, o.Namespace)
		tp.SetRecorder(rec)
		provider = tp
	}

	res, trace, err := client.Diagnose(ctx, clean, provider)
	if err != nil {
		writeAudit(o.AuditWriter, rec, nil, "")
		return nil, clean, trace, err
	}
	if tp != nil {
		if denied := tp.DeniedCalls(); len(denied) > 0 {
			warn := "SECURITY: the agent attempted to read outside namespace " + o.Namespace +
				" and was refused: " + strings.Join(denied, ", ") +
				". This can indicate prompt injection via application logs — inspect the bundle."
			if res != nil {
				res.Notes = strings.TrimSpace(warn + " " + res.Notes)
			}
		}
	}

	writeAudit(o.AuditWriter, rec, res, marshalResult(res))
	return res, clean, trace, nil
}

// writeAudit finalizes and emits the audit record (best-effort; audit failure
// must not fail a diagnosis).
func writeAudit(w io.Writer, rec *audit.Recorder, res *llm.Result, resultJSON string) {
	if w == nil {
		return
	}
	summary, insufficient := "", false
	if res != nil {
		summary, insufficient = res.Summary, res.InsufficientEvidence
	}
	_ = audit.WriteJSON(w, rec.Finish(summary, insufficient, resultJSON))
}

func marshalResult(r *llm.Result) string {
	if r == nil {
		return ""
	}
	b, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return string(b)
}

// RenderJSON writes the result as indented JSON.
func RenderJSON(w io.Writer, r *llm.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// safe strips control characters (everything except \n and \t) from model
// output before it reaches the operator's terminal. Model text is derived from
// attacker-influenceable logs; an ANSI escape sequence smuggled through the
// model must not be able to rewrite what the operator sees.
func safe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return -1
		}
		return r
	}, s)
}

// RenderText writes a compact human-readable report. trace lists the tool calls
// the agent made (may be empty). All model-derived strings are passed through
// safe() first.
func RenderText(w io.Writer, ns, pod string, r *llm.Result, trace []string) {
	fmt.Fprintf(w, "\nRCA for %s/%s\n", ns, pod)
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 60))
	fmt.Fprintf(w, "Summary: %s\n", safe(r.Summary))
	if r.InsufficientEvidence {
		fmt.Fprintln(w, "\n[!] Insufficient evidence — the steps below would disambiguate.")
	}

	if len(r.LikelyCauses) > 0 {
		fmt.Fprintln(w, "\nLikely causes:")
		for i, c := range r.LikelyCauses {
			fmt.Fprintf(w, "  %d. [%s] %s\n", i+1, safe(strings.ToUpper(c.Confidence)), safe(c.Cause))
			for _, e := range c.Evidence {
				fmt.Fprintf(w, "       - %s\n", safe(e))
			}
		}
	}
	if len(r.RecommendedNextSteps) > 0 {
		fmt.Fprintln(w, "\nNext steps (read-only):")
		for _, s := range r.RecommendedNextSteps {
			fmt.Fprintf(w, "  - %s\n", safe(s))
		}
	}
	if len(r.SuggestedRemediation) > 0 {
		fmt.Fprintln(w, "\nSuggested remediation (review before applying):")
		for _, s := range r.SuggestedRemediation {
			fmt.Fprintf(w, "  - %s\n", safe(s))
		}
	}
	if strings.TrimSpace(r.Notes) != "" {
		fmt.Fprintf(w, "\nNotes: %s\n", safe(r.Notes))
	}
	if len(trace) > 0 {
		fmt.Fprintln(w, "\nAgent investigated (read-only tool calls):")
		for _, t := range trace {
			fmt.Fprintf(w, "  - %s\n", safe(t))
		}
	}
}
