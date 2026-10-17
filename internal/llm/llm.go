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
	"strings"
	"time"
)

//go:embed system_prompt.md
var systemPrompt string

// SystemPrompt returns the base system prompt. Exposed so the audit layer can
// hash it — the prompt version is part of what makes a run explainable.
func SystemPrompt() string { return systemPrompt }

const (
	defaultTimeout = 90 * time.Second

	// maxResponseBytes bounds how much of an LLM backend's response body we
	// will read. A hostile or broken --base-url endpoint must not be able to
	// exhaust memory; an RCA is a few KB.
	maxResponseBytes = 8 << 20

	// DefaultAnthropicModel is used when --provider=anthropic.
	DefaultAnthropicModel = "claude-sonnet-4-6"
	// DefaultOpenAICompatModel is a placeholder; self-hosted deployments must
	// pass --model explicitly since the served name varies.
	DefaultOpenAICompatModel = "qwen2.5:14b"
)

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

// Provider is an LLM backend capable of running the diagnostic tool-use loop.
// It returns the parsed RCA plus a trace of the tool calls made (for audit).
type Provider interface {
	Diagnose(ctx context.Context, bundle string, tp ToolProvider) (*Result, []string, error)
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
func parseResultText(text string) (*Result, error) {
	jsonStr := extractJSON(text)
	var out Result
	if err := json.Unmarshal([]byte(jsonStr), &out); err != nil {
		return nil, fmt.Errorf("parse model JSON: %w\nraw model output:\n%s", err, text)
	}
	// A JSON object that parses but carries no summary is not an RCA — for
	// example a stray object the model echoed from attacker-controlled logs.
	// Rendering it would print an empty report that reads as "nothing found",
	// which is the worst way for a diagnostic tool to fail. Fail loudly instead.
	if strings.TrimSpace(out.Summary) == "" {
		return nil, fmt.Errorf("model returned no usable RCA (empty summary)\nraw model output:\n%s", text)
	}
	return &out, nil
}

// extractJSON returns the last balanced top-level {...} object in s. The model's
// final answer is always last; any earlier JSON-looking text (e.g. a simulated
// tool call, or narration) is ignored. Brace matching is string-aware so braces
// inside string values don't throw off the depth count.
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
			inStr = true
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

// Compile-time assertions: both backends must satisfy Provider.
var (
	_ Provider = (*anthropicProvider)(nil)
	_ Provider = (*openAICompatProvider)(nil)
)
