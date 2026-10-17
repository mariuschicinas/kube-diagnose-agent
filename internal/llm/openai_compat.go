package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// openAICompatProvider talks to any endpoint implementing OpenAI's
// /v1/chat/completions with function calling. That one interface covers:
//
//	Ollama    --base-url http://localhost:11434/v1        (dev / laptop)
//	vLLM      --base-url http://vllm.internal:8000/v1     (self-hosted, in-cluster)
//	LiteLLM   --base-url http://litellm.internal:4000/v1  (proxy to Bedrock/Azure/etc)
//	OpenAI    --base-url https://api.openai.com/v1
//
// The agent itself operates no inference service — it is only an HTTP client.
// Where inference runs is the operator's infrastructure decision, and it does
// not change the agent's security posture: the boundaries are RBAC and the
// namespace allowlist, not the choice of model.
type openAICompatProvider struct {
	httpc     *http.Client
	baseURL   string
	apiKey    string // may be empty (local Ollama / in-VPC vLLM often need no auth)
	model     string
	maxTokens int
	maxIter   int
}

func newOpenAICompat(c Config) (Provider, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		return nil, fmt.Errorf("--base-url is required for provider=openai-compat " +
			"(e.g. http://localhost:11434/v1 for Ollama, http://vllm.internal:8000/v1 for vLLM)")
	}
	model := c.Model
	if model == "" {
		model = DefaultOpenAICompatModel
	}
	maxTokens := c.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 2048
	}
	// An API key is optional: a local or in-VPC endpoint typically has none.
	var key string
	if c.APIKeyEnv != "" {
		key = os.Getenv(c.APIKeyEnv)
	}
	// A bearer token over plaintext HTTP to a non-local host leaks the key to
	// anyone on the path. Warn loudly; do not block (in-VPC http is a valid
	// operator choice).
	if key != "" {
		if u, perr := url.Parse(base); perr == nil && u.Scheme == "http" && !isLocalHost(u.Hostname()) {
			fmt.Fprintf(os.Stderr, "WARNING: --base-url %s uses plaintext http with an API key; the key is sent unencrypted\n", base)
		}
	}
	return &openAICompatProvider{
		httpc:     &http.Client{Timeout: defaultTimeout},
		baseURL:   base,
		apiKey:    key,
		model:     model,
		maxTokens: maxTokens,
		maxIter:   c.MaxIterations,
	}, nil
}

// isLocalHost reports whether host is loopback or a private (RFC 1918 / ULA)
// address, where plaintext HTTP is an acceptable operator choice.
func isLocalHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // a DNS name: assume it may leave the host
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

// --- wire types (OpenAI chat-completions shape) ---

type oaiReq struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens,omitempty"`
	Messages  []oaiMsg  `json:"messages"`
	Tools     []oaiTool `json:"tools,omitempty"`
}

type oaiMsg struct {
	Role    string        `json:"role"` // system | user | assistant | tool
	Content string        `json:"content,omitempty"`
	ToolCls []oaiToolCall `json:"tool_calls,omitempty"` // assistant turns
	// tool result turns:
	ToolCallID string `json:"tool_call_id,omitempty"`
}

type oaiTool struct {
	Type     string      `json:"type"` // "function"
	Function oaiFuncDecl `json:"function"`
}

type oaiFuncDecl struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type oaiToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name string `json:"name"`
		// Arguments is a JSON *string* in this API, not an object.
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type oaiResp struct {
	Choices []struct {
		Message struct {
			Content   string        `json:"content"`
			ToolCalls []oaiToolCall `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// toOAITools adapts our provider-agnostic ToolDef to OpenAI's function shape.
func toOAITools(defs []ToolDef) []oaiTool {
	out := make([]oaiTool, 0, len(defs))
	for _, d := range defs {
		out = append(out, oaiTool{
			Type: "function",
			Function: oaiFuncDecl{
				Name:        d.Name,
				Description: d.Description,
				Parameters:  d.InputSchema,
			},
		})
	}
	return out
}

// Diagnose runs the tool-use loop against an OpenAI-compatible endpoint.
func (p *openAICompatProvider) Diagnose(ctx context.Context, bundle string, tp ToolProvider) (*Result, []string, error) {
	var tools []oaiTool
	if tp != nil {
		tools = toOAITools(tp.Defs())
	}

	// System message is rebuilt each round so tool guidance appears only when
	// tools are actually offered.
	messages := []oaiMsg{
		{Role: "system", Content: systemFor(tp != nil && p.maxIter > 0)},
		{Role: "user", Content: userPrompt(bundle)},
	}

	var trace []string
	for round := 0; ; round++ {
		// Hard cap: maxIter tool rounds plus one forced-conclusion round. With
		// the offered-tools check below this cannot normally trigger; it stays as
		// a backstop so no code path can spin the loop until the deadline.
		if round > p.maxIter {
			return nil, trace, fmt.Errorf("model did not conclude within %d rounds", p.maxIter+1)
		}
		offerTools := tp != nil && round < p.maxIter
		messages[0].Content = systemFor(offerTools)

		req := oaiReq{
			Model:     p.model,
			MaxTokens: p.maxTokens,
			Messages:  messages,
		}
		if offerTools {
			req.Tools = tools
		}

		resp, err := p.call(ctx, req)
		if err != nil {
			return nil, trace, err
		}
		if len(resp.Choices) == 0 {
			return nil, trace, fmt.Errorf("backend returned no choices")
		}
		msg := resp.Choices[0].Message

		if len(msg.ToolCalls) == 0 {
			res, err := parseResultText(msg.Content)
			return res, trace, err
		}

		// Tools are executed only in rounds where they were offered. A backend
		// that returns tool calls anyway (weaker openai-compat models do) is an
		// error, not something to act on — and with --max-iterations 0 there is
		// no tool provider at all, so calling it would panic.
		if !offerTools || tp == nil {
			return nil, trace, fmt.Errorf("model requested tools in round %d, where none were offered", round)
		}

		// Echo the assistant's tool-call turn back, then append one tool result
		// message per call — the shape this API requires.
		messages = append(messages, oaiMsg{
			Role:    "assistant",
			Content: msg.Content,
			ToolCls: msg.ToolCalls,
		})

		for _, tc := range msg.ToolCalls {
			args := json.RawMessage(tc.Function.Arguments)
			trace = append(trace, fmt.Sprintf("%s(%s)", tc.Function.Name, tc.Function.Arguments))

			content, rerr := tp.Run(ctx, tc.Function.Name, args)
			if rerr != nil {
				// Smaller models fabricate tool names and malformed arguments far
				// more often than frontier models. Feeding the error back lets the
				// model correct itself; the namespace allowlist has already refused
				// anything out of scope regardless.
				content = "tool error: " + rerr.Error()
			}
			messages = append(messages, oaiMsg{
				Role:       "tool",
				ToolCallID: tc.ID,
				Content:    content,
			})
		}
	}
}

func (p *openAICompatProvider) call(ctx context.Context, req oaiReq) (*oaiResp, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	url := p.baseURL + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("content-type", "application/json")
	if p.apiKey != "" {
		httpReq.Header.Set("authorization", "Bearer "+p.apiKey)
	}

	resp, err := p.httpc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("call %s: %w", url, err)
	}
	defer resp.Body.Close()

	var or oaiResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&or); err != nil {
		return nil, fmt.Errorf("decode response (status %d) from %s: %w", resp.StatusCode, url, err)
	}
	if or.Error != nil {
		return nil, fmt.Errorf("backend error: %s: %s", or.Error.Type, or.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("backend returned status %d", resp.StatusCode)
	}
	return &or, nil
}
