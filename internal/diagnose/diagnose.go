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
	// MaxLogBytes caps the bytes fetched per container instance (<= 0: default).
	MaxLogBytes int64

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

// Report is everything a run produced, whether or not it succeeded.
type Report struct {
	Result *llm.Result
	// Bundle is the redacted bundle that was sent, so callers can show exactly
	// what left the cluster. Empty if collection itself failed.
	Bundle string
	// Trace lists the tool calls the agent made, in order.
	Trace []string
	// Denied lists tool calls refused by the namespace allowlist — an attempt
	// is itself a tampering signal and is surfaced even when the run fails.
	Denied []string
	// AuditErr is non-nil when an audit record was requested but could not be
	// written. The run is not failed for it; the caller decides.
	AuditErr error
}

// Run executes the full pipeline. The Report is never nil: on error it still
// carries whatever was produced before the failure.
func Run(ctx context.Context, cs kubernetes.Interface, o Options) (*Report, error) {
	rep := &Report{}

	// The recorder exists before anything else happens, so a 403 from the API
	// server or a missing API key still leaves an audit record.
	rec := audit.New(o.AgentVersion, o.Namespace, o.Pod, o.Provider, o.Model,
		o.Initiator, llm.SystemPrompt(), llm.ToolSystemPrompt(), o.MaxIterations)
	finish := func(err error) error {
		rep.AuditErr = writeAudit(o.AuditWriter, rec, rep.Result, err)
		return err
	}

	bundle, err := collect.New(cs, o.Tail, o.MaxLogBytes).Gather(ctx, o.Namespace, o.Pod)
	if err != nil {
		return rep, finish(err)
	}
	rep.Bundle = redact.Scrub(bundle.Text)
	rec.SetBundle(rep.Bundle)

	client, err := llm.NewProvider(llm.Config{
		Kind:          o.Provider,
		Model:         o.Model,
		BaseURL:       o.BaseURL,
		APIKeyEnv:     o.APIKeyEnv,
		MaxTokens:     o.MaxTokens,
		MaxIterations: o.MaxIterations,
	})
	if err != nil {
		return rep, finish(err)
	}
	info := client.Info()
	rec.SetProvider(info.Kind, info.Model, info.Endpoint)

	var provider llm.ToolProvider
	var tp *tools.Provider
	if o.MaxIterations > 0 {
		// The provider is locked to the target Pod's namespace: reads elsewhere
		// are refused in code, regardless of what the model is talked into.
		tp = tools.New(cs, o.Namespace)
		tp.SetRecorder(rec)
		provider = tp
	}

	res, trace, err := client.Diagnose(ctx, rep.Bundle, provider)
	rep.Result, rep.Trace = res, trace
	if tp != nil {
		rep.Denied = tp.DeniedCalls()
	}
	if err != nil {
		return rep, finish(err)
	}
	if len(rep.Denied) > 0 && res != nil {
		res.Notes = strings.TrimSpace(DeniedWarning(o.Namespace, rep.Denied) + " " + res.Notes)
	}
	return rep, finish(nil)
}

// DeniedWarning is the SECURITY notice for refused cross-namespace reads. It
// is placed in the RCA notes on success and printed by the CLI on failure.
func DeniedWarning(ns string, denied []string) string {
	return "SECURITY: the agent attempted to read outside namespace " + ns +
		" and was refused: " + strings.Join(denied, ", ") +
		". This can indicate prompt injection via application logs — inspect the bundle."
}

// writeAudit finalizes and emits the audit record. The error is returned, not
// swallowed: a full disk must not silently produce a run with no record.
func writeAudit(w io.Writer, rec *audit.Recorder, res *llm.Result, runErr error) error {
	if w == nil {
		return nil
	}
	summary, insufficient, resultJSON := "", false, ""
	if res != nil {
		summary, insufficient, resultJSON = res.Summary, res.InsufficientEvidence, marshalResult(res)
	}
	return audit.WriteJSON(w, rec.Finish(summary, insufficient, resultJSON, runErr))
}

func marshalResult(r *llm.Result) string {
	b, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return string(b)
}

// RenderJSON writes the result and the tool trace as indented JSON:
// {"result": {...}, "tool_trace": [...]}. HTML escaping is off: the consumer
// is a pipeline, not a browser, and "<" for "<" only obscures the
// evidence.
func RenderJSON(w io.Writer, r *llm.Result, trace []string) error {
	if trace == nil {
		trace = []string{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(struct {
		Result    *llm.Result `json:"result"`
		ToolTrace []string    `json:"tool_trace"`
	}{r, trace})
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
