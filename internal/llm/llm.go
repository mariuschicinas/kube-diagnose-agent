// Package llm turns a diagnostic bundle into a structured RCA, optionally
// running an agentic tool-use loop first.
//
// The package is provider-agnostic: a Provider is anything that can run the
// loop and return a Result. Two implementations ship here — Anthropic's
// Messages API and any OpenAI-compatible /v1/chat/completions endpoint (which
// covers Ollama, vLLM, LiteLLM, Bedrock-via-gateway, and OpenAI itself).
//
// Note what does NOT change when the provider changes: collection, redaction,
// the untrusted-log fence, the tool set, and the namespace allowlist. The
// security boundaries live in RBAC and in code, not in the choice of model.
package llm

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"kube-diagnose-agent/internal/sanitize"
)

//go:embed system_prompt.md
var systemPrompt string

// SystemPrompt returns the base system prompt. Exposed so the audit layer can
// hash it — the prompt version is part of what makes a run explainable.
func SystemPrompt() string { return systemPrompt }

// ToolSystemPrompt returns the system prompt as sent on rounds where tools are
// offered (base prompt + tool guidance). The audit layer hashes this one too:
// a change to the tool guidance changes model behaviour just as much.
func ToolSystemPrompt() string { return systemFor(true) }

const (
	// CallTimeout bounds one HTTP call to the backend. The run deadline in
	// cmd/agent is derived from it and the number of rounds.
	CallTimeout = 90 * time.Second

	// maxResponseBytes bounds how much of an LLM backend's response body we
	// will read. A hostile or broken --base-url endpoint must not be able to
	// exhaust memory; an RCA is a few KB.
	maxResponseBytes = 8 << 20

	// maxToolCallsPerRound caps how many tool calls one model response may
	// trigger. The round budget (--max-iterations) bounds rounds, not calls;
	// without this one response carrying 50 calls would mean 50 cluster reads.
	maxToolCallsPerRound = 5

	// maxLikelyCauses is what the prompt asks for; a longer list is cut.
	maxLikelyCauses = 3

	// maxAttempts is the number of HTTP attempts per call (1 + retries) on
	// transient failures: 429, 5xx, 529 and network errors.
	maxAttempts = 3

	// DefaultAnthropicModel is used when --provider=anthropic.
	DefaultAnthropicModel = "claude-sonnet-4-6"
	// DefaultOpenAICompatModel is a placeholder; self-hosted deployments must
	// pass --model explicitly since the served name varies.
	DefaultOpenAICompatModel = "qwen2.5:14b"
)

// retryBase is the first backoff delay (doubled per attempt). A variable so
// tests can zero it.
var retryBase = defaultRetryBase

const defaultRetryBase = time.Second

// toolGuidance is appended to the system prompt ONLY on rounds where read-only
// tools are actually offered. Keeping it out of the base prompt means
// single-shot runs (and the final forced-conclusion round) never advertise
// tools, so the model won't try to simulate tool calls as text.
const toolGuidance = `You have a set of READ-ONLY tools available (their names and inputs are provided separately). Use them to CONFIRM a hypothesis before concluding rather than guessing — e.g. if a log line references a dependency like "db:5432", check whether that Service exists and has endpoints.

Before calling a tool, ask: is this object actually ON the failure path? Call it only if the answer is yes AND the result would confirm or change your conclusion. Availability of a tool is not a reason to call it; a clean run with zero tool calls is a good outcome when the bundle already explains the failure.

On the failure path (worth confirming):
- The Pod's app logs a connection failure to a named dependency -> get_service / get_endpoints for THAT dependency.
- A dependency Pod is implicated -> get_pod for that Pod.

NOT on the failure path (do not call):
- Kubelet probes (liveness/readiness/startup) connect DIRECTLY to the Pod IP. They never traverse a Service. A probe failure tells you nothing about any Service, so do not look up a Service when diagnosing a probe failure.
- Image pull failures happen at the container runtime, before networking. No Service or endpoint is involved.
- OOMKills and in-process crashes with no dependency in the logs need no cluster lookups.

Interpreting results:
- Use the same namespace as the target Pod unless the evidence names another.
- A NOT FOUND is strong, confirmed evidence ONLY IF that object was required for the failing path. A NOT FOUND for an object that was never needed proves nothing — do not cite it as evidence and do not let it inflate a cause's confidence.
- Zero ready endpoints for a Service the app is trying to reach explains "connection refused".
- Your tool budget is limited. When you have enough evidence, stop calling tools and return the final JSON.`

// Cause is one candidate root cause.
type Cause struct {
	Cause      string   `json:"cause"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence"`
}

// UnmarshalJSON accepts confidence as a string ("high") or a number (0.8, 80)
// — smaller models produce both — and normalises it to high|medium|low, or
// "unknown" when it is neither. A single odd field must not fail the whole RCA.
func (c *Cause) UnmarshalJSON(b []byte) error {
	var aux struct {
		Cause      string          `json:"cause"`
		Confidence json.RawMessage `json:"confidence"`
		Evidence   []string        `json:"evidence"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	c.Cause = aux.Cause
	c.Evidence = aux.Evidence
	c.Confidence = normalizeConfidence(aux.Confidence)
	return nil
}

func normalizeConfidence(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.ToLower(strings.TrimSpace(s))
		switch {
		case strings.Contains(s, "high"):
			return "high"
		case strings.Contains(s, "med"):
			return "medium"
		case strings.Contains(s, "low"):
			return "low"
		}
		return "unknown"
	}
	var n float64
	if err := json.Unmarshal(raw, &n); err == nil {
		if n > 1 { // percent
			n /= 100
		}
		switch {
		case n >= 0.75:
			return "high"
		case n >= 0.4:
			return "medium"
		case n >= 0:
			return "low"
		}
	}
	return "unknown"
}

// Result is the structured RCA returned by the model.
type Result struct {
	Summary              string   `json:"summary"`
	InsufficientEvidence bool     `json:"insufficient_evidence"`
	LikelyCauses         []Cause  `json:"likely_causes"`
	RecommendedNextSteps []string `json:"recommended_next_steps"`
	SuggestedRemediation []string `json:"suggested_remediation"`
	Notes                string   `json:"notes"`
}

// ToolDef describes a read-only tool exposed to the model. The shape matches
// Anthropic's API; the OpenAI-compatible provider adapts it on the wire.
type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// ToolProvider supplies tool definitions and executes tool calls. Implemented
// outside this package (internal/tools) so llm stays free of any Kubernetes
// dependency.
type ToolProvider interface {
	Defs() []ToolDef
	Run(ctx context.Context, name string, input json.RawMessage) (string, error)
}

// ProviderInfo is what a Provider resolved from its Config: the model actually
// requested and the endpoint actually called (credentials and query stripped).
// The audit record stores these, not the flags the operator typed.
type ProviderInfo struct {
	Kind     string
	Model    string
	Endpoint string
}

// Provider is an LLM backend capable of running the diagnostic tool-use loop.
// It returns the parsed RCA plus a trace of the tool calls made (for audit).
type Provider interface {
	Diagnose(ctx context.Context, bundle string, tp ToolProvider) (*Result, []string, error)
	Info() ProviderInfo
}

// Config selects and configures a Provider.
type Config struct {
	// Kind is "anthropic" or "openai-compat".
	Kind string
	// Model is the model name/identifier served by the backend.
	Model string
	// BaseURL overrides the endpoint (openai-compat only). Examples:
	//   Ollama    http://localhost:11434/v1
	//   vLLM      http://vllm.internal:8000/v1
	//   LiteLLM   http://litellm.internal:4000/v1
	//   OpenAI    https://api.openai.com/v1
	BaseURL string
	// APIKeyEnv names the environment variable holding the API key. Empty means
	// no auth header is sent (typical for a local Ollama or an in-VPC vLLM).
	APIKeyEnv     string
	MaxTokens     int
	MaxIterations int
}

// NewProvider builds the configured Provider.
func NewProvider(c Config) (Provider, error) {
	switch strings.ToLower(c.Kind) {
	case "", "anthropic":
		return newAnthropic(c)
	case "openai-compat", "openai":
		return newOpenAICompat(c)
	default:
		return nil, fmt.Errorf("unknown provider %q (want: anthropic, openai-compat)", c.Kind)
	}
}

// systemFor returns the system prompt, with tool guidance appended only when
// tools are actually being offered this round.
func systemFor(offerTools bool) string {
	if offerTools {
		return systemPrompt + "\n\n" + toolGuidance
	}
	return systemPrompt
}

// userPrompt wraps the bundle for the first user turn.
func userPrompt(bundle string) string {
	return "Diagnostic bundle for one Pod follows. Investigate with tools if useful, then produce the JSON RCA.\n\n" + bundle
}

// parseResultText extracts and unmarshals the final JSON object from model text.
//
// Every string field is normalised (sanitize.Normalize) BEFORE the read-only
// filter runs and is stored in that form, so the text the filter inspected is
// exactly the text the report prints. Filtering the raw string and normalising
// at render time would let a zero-width character hide "exec" from the filter
// and then vanish on screen.
func parseResultText(text string) (*Result, error) {
	jsonStr := extractJSON(text)
	var out Result
	if err := json.Unmarshal([]byte(jsonStr), &out); err != nil {
		return nil, fmt.Errorf("parse model JSON: %w\nraw model output (excerpt):\n%s", err, excerpt(text))
	}
	// A JSON object that parses but carries no summary is not an RCA — for
	// example a stray object the model echoed from attacker-controlled logs.
	// Rendering it would print an empty report that reads as "nothing found",
	// which is the worst way for a diagnostic tool to fail. Fail loudly instead.
	if strings.TrimSpace(out.Summary) == "" {
		return nil, fmt.Errorf("model returned no usable RCA (empty summary)\nraw model output (excerpt):\n%s", excerpt(text))
	}
	normalizeResult(&out)
	enforceReadOnlySteps(&out)
	flagRemediation(&out)
	return &out, nil
}

// normalizeResult canonicalises every model-supplied string in place and
// enforces the structural limits the prompt asks for.
func normalizeResult(r *Result) {
	r.Summary = sanitize.Normalize(r.Summary)
	r.Notes = sanitize.Normalize(r.Notes)
	if len(r.LikelyCauses) > maxLikelyCauses {
		dropped := len(r.LikelyCauses) - maxLikelyCauses
		r.LikelyCauses = r.LikelyCauses[:maxLikelyCauses]
		r.Notes = strings.TrimSpace(fmt.Sprintf("Model listed %d extra cause(s) beyond the %d requested; they were dropped. %s",
			dropped, maxLikelyCauses, r.Notes))
	}
	for i := range r.LikelyCauses {
		c := &r.LikelyCauses[i]
		c.Cause = sanitize.Normalize(c.Cause)
		c.Confidence = sanitize.Normalize(c.Confidence)
		for j := range c.Evidence {
			c.Evidence[j] = sanitize.Normalize(c.Evidence[j])
		}
	}
	for i := range r.RecommendedNextSteps {
		r.RecommendedNextSteps[i] = sanitize.Normalize(r.RecommendedNextSteps[i])
	}
	for i := range r.SuggestedRemediation {
		r.SuggestedRemediation[i] = sanitize.Normalize(r.SuggestedRemediation[i])
	}
}

// maxErrorExcerpt bounds how much raw model output an error message carries.
const maxErrorExcerpt = 2048

// excerpt makes raw model output safe to print in an error: control
// characters stripped (the error goes straight to the operator's terminal)
// and the size bounded.
func excerpt(text string) string {
	return sanitize.Truncate(sanitize.Terminal(text), maxErrorExcerpt)
}

// extractJSON returns the last balanced top-level {...} object in s. The model's
// final answer is always last; any earlier JSON-looking text (e.g. a simulated
// tool call, or narration) is ignored. Brace matching is string-aware so braces
// inside string values don't throw off the depth count — but only inside an
// object: a stray quote in the prose around the JSON ("the "db service) must
// not flip the string state and hide the real object.
//
// This matters more, not less, with smaller self-hosted models: they narrate
// around their JSON far more often than frontier models do.
func extractJSON(s string) string {
	depth := 0
	start := -1
	inStr := false
	esc := false
	best := ""
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			if depth > 0 {
				inStr = true
			}
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 && start >= 0 {
					best = s[start : i+1] // keep the last complete object
				}
			}
		}
	}
	if best != "" {
		return best
	}
	return strings.TrimSpace(s)
}

// doWithRetry performs an HTTP call with bounded retries on transient
// failures: network errors, 429, 5xx and Anthropic's 529. build is called per
// attempt so the body reader is fresh. Retry-After is honoured (capped), else
// the delay doubles from retryBase. The last response is returned as-is so the
// caller reports its status.
func doWithRetry(ctx context.Context, httpc *http.Client, build func() (*http.Request, error)) (*http.Response, error) {
	var lastErr error
	delay := retryBase
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, delay); err != nil {
				return nil, fmt.Errorf("%w (last error: %v)", err, lastErr)
			}
			delay *= 2
		}
		req, err := build()
		if err != nil {
			return nil, err
		}
		resp, err := httpc.Do(req)
		if err != nil {
			// net/http embeds the request URL in its error — with the query
			// string, which may carry a key. Strip it before the error can be
			// printed or audited.
			if ue, ok := err.(*url.Error); ok {
				ue.URL = redactURL(ue.URL)
			}
			if ctx.Err() != nil {
				return nil, err
			}
			lastErr = err
			continue
		}
		if !retryableStatus(resp.StatusCode) || attempt == maxAttempts-1 {
			return resp, nil
		}
		lastErr = fmt.Errorf("backend returned status %d", resp.StatusCode)
		if ra := retryAfter(resp.Header); ra > 0 {
			delay = ra
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
	}
	return nil, fmt.Errorf("after %d attempts: %w", maxAttempts, lastErr)
}

func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout, 529:
		return true
	}
	return false
}

// retryAfter parses a Retry-After header given in seconds; 0 when absent or
// unusable. Capped so a hostile backend cannot park the run.
func retryAfter(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	secs, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || secs <= 0 {
		return 0
	}
	d := time.Duration(secs) * time.Second
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// redactURL strips user info and the query string from a URL before it is
// shown in an error or stored in the audit record: both can carry credentials
// (https://user:pass@gw/v1, ?key=...).
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparseable url)"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// Compile-time assertions: both backends must satisfy Provider.
var (
	_ Provider = (*anthropicProvider)(nil)
	_ Provider = (*openAICompatProvider)(nil)
)
