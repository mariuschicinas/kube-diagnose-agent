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

	"kube-diagnose-agent/internal/audit"
	"kube-diagnose-agent/internal/collect"
	"kube-diagnose-agent/internal/llm"
	"kube-diagnose-agent/internal/redact"
	"kube-diagnose-agent/internal/sanitize"
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

// RenderJSON writes the result as indented JSON. HTML escaping is off: the
// consumer is a pipeline, not a browser, and "<" for "<" only obscures
// the evidence.
func RenderJSON(w io.Writer, r *llm.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// block prepares one model-derived value for the terminal: control characters
// stripped (sanitize.Terminal), and every embedded newline indented so the
// value cannot start a line at column 0 and forge a report heading such as
// "Next steps (read-only):" above a command of its own choosing.
func block(s string) string {
	return strings.ReplaceAll(sanitize.Terminal(s), "\n", "\n      ")
}

// RenderText writes a compact human-readable report. trace lists the tool calls
// the agent made (may be empty). All model-derived strings are passed through
// block() first.
func RenderText(w io.Writer, ns, pod string, r *llm.Result, trace []string) {
	fmt.Fprintf(w, "\nRCA for %s/%s\n", ns, pod)
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 60))
	fmt.Fprintf(w, "Summary: %s\n", block(r.Summary))
	if r.InsufficientEvidence {
		fmt.Fprintln(w, "\n[!] Insufficient evidence — the steps below would disambiguate.")
	}

	if len(r.LikelyCauses) > 0 {
		fmt.Fprintln(w, "\nLikely causes:")
		for i, c := range r.LikelyCauses {
			fmt.Fprintf(w, "  %d. [%s] %s\n", i+1, block(strings.ToUpper(c.Confidence)), block(c.Cause))
			for _, e := range c.Evidence {
				fmt.Fprintf(w, "       - %s\n", block(e))
			}
		}
	}
	if len(r.RecommendedNextSteps) > 0 {
		fmt.Fprintln(w, "\nNext steps (read-only):")
		for _, s := range r.RecommendedNextSteps {
			fmt.Fprintf(w, "  - %s\n", block(s))
		}
	}
	if len(r.SuggestedRemediation) > 0 {
		fmt.Fprintln(w, "\nSuggested remediation (review before applying):")
		for _, s := range r.SuggestedRemediation {
			fmt.Fprintf(w, "  - %s\n", block(s))
		}
	}
	if strings.TrimSpace(r.Notes) != "" {
		fmt.Fprintf(w, "\nNotes: %s\n", block(r.Notes))
	}
	if len(trace) > 0 {
		fmt.Fprintln(w, "\nAgent investigated (read-only tool calls):")
		for _, t := range trace {
			fmt.Fprintf(w, "  - %s\n", block(t))
		}
	}
}
