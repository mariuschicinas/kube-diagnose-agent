package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const (
	anthropicURL     = "https://api.anthropic.com/v1/messages"
	anthropicVersion = "2023-06-01"
)

// anthropicProvider talks to the Anthropic Messages API. It uses only net/http
// to keep the dependency surface small.
type anthropicProvider struct {
	httpc     *http.Client
	url       string // anthropicURL; a field so tests can point it at httptest
	apiKey    string
	model     string
	maxTokens int
	maxIter   int
}

func newAnthropic(c Config) (Provider, error) {
	keyEnv := c.APIKeyEnv
	if keyEnv == "" {
		keyEnv = "ANTHROPIC_API_KEY"
	}
	key := os.Getenv(keyEnv)
	if key == "" {
		return nil, fmt.Errorf("%s is not set", keyEnv)
	}
	model := c.Model
	if model == "" {
		model = DefaultAnthropicModel
	}
	maxTokens := c.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 2048
	}
	return &anthropicProvider{
		httpc:     &http.Client{Timeout: CallTimeout},
		url:       anthropicURL,
		apiKey:    key,
		model:     model,
		maxTokens: maxTokens,
		maxIter:   c.MaxIterations,
	}, nil
}

func (p *anthropicProvider) Info() ProviderInfo {
	return ProviderInfo{Kind: "anthropic", Model: p.model, Endpoint: redactURL(p.url)}
}

// --- wire types ---

type anthReq struct {
	Model      string          `json:"model"`
	MaxTokens  int             `json:"max_tokens"`
	System     string          `json:"system"`
	Tools      []ToolDef       `json:"tools,omitempty"`
	ToolChoice *anthToolChoice `json:"tool_choice,omitempty"`
	Messages   []anthMsg       `json:"messages"`
}

type anthToolChoice struct {
	Type string `json:"type"` // "auto" | "any" | "tool" | "none"
}

type anthMsg struct {
	Role    string      `json:"role"`
	Content []anthBlock `json:"content"`
}

// anthBlock is a polymorphic block used for both requests and responses.
type anthBlock struct {
	Type string `json:"type"`
	// text
	Text string `json:"text,omitempty"`
	// tool_use (from the model)
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
	// tool_result (to the model)
	ToolUseID string `json:"tool_use_id,omitempty"`
	Content   string `json:"content,omitempty"`
	IsError   bool   `json:"is_error,omitempty"`
}

type anthResp struct {
	Content    []anthBlock `json:"content"`
	StopReason string      `json:"stop_reason"`
	Error      *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// Diagnose runs the tool-use loop against Anthropic.
func (p *anthropicProvider) Diagnose(ctx context.Context, bundle string, tp ToolProvider) (*Result, []string, error) {
	messages := []anthMsg{{
		Role:    "user",
		Content: []anthBlock{{Type: "text", Text: userPrompt(bundle)}},
	}}

	var tools []ToolDef
	if tp != nil {
		tools = tp.Defs()
	}

	var trace []string
	totalCalls := 0
	for round := 0; ; round++ {
		// Hard cap: maxIter tool rounds plus one forced-conclusion round. With
		// the offered-tools check below this cannot normally trigger; it stays as
		// a backstop so no code path can spin the loop until the deadline.
		if round > p.maxIter {
			return nil, trace, fmt.Errorf("model did not conclude within %d rounds", p.maxIter+1)
		}
		offerTools := tp != nil && round < p.maxIter

		req := anthReq{
			Model:     p.model,
			MaxTokens: p.maxTokens,
			System:    systemFor(offerTools),
			Messages:  messages,
		}
		// The API requires `tools` on every request whose history contains
		// tool_use/tool_result blocks, so the definitions are always sent once
		// a tool provider exists. On the forced-conclusion round tool_choice
		// "none" withdraws them: the model must answer with text.
		if tp != nil {
			req.Tools = tools
			if !offerTools {
				req.ToolChoice = &anthToolChoice{Type: "none"}
			}
		}

		resp, err := p.call(ctx, req)
		if err != nil {
			return nil, trace, err
		}
		if resp.StopReason == "max_tokens" {
			return nil, trace, fmt.Errorf("model output was cut off at %d tokens (stop_reason=max_tokens); raise --max-tokens", p.maxTokens)
		}
		messages = append(messages, anthMsg{Role: "assistant", Content: resp.Content})

		var toolUses []anthBlock
		for _, b := range resp.Content {
			if b.Type == "tool_use" {
				toolUses = append(toolUses, b)
			}
		}
		if len(toolUses) == 0 {
			var text strings.Builder
			for _, b := range resp.Content {
				if b.Type == "text" {
					text.WriteString(b.Text)
				}
			}
			res, err := parseResultText(text.String())
			return res, trace, err
		}

		// Tools are executed only in rounds where they were offered. A backend
		// that returns tool calls anyway is an error, not something to act on —
		// and with --max-iterations 0 there is no tool provider at all, so
		// calling it would panic.
		if !offerTools || tp == nil {
			return nil, trace, fmt.Errorf("model requested tools in round %d, where none were offered", round)
		}

		var results []anthBlock
		for i, tu := range toolUses {
			block := anthBlock{Type: "tool_result", ToolUseID: tu.ID}
			if why := overBudget(i, totalCalls, p.maxIter); why != "" {
				block.Content, block.IsError = "tool error: "+why, true
				results = append(results, block)
				continue
			}
			totalCalls++
			trace = append(trace, fmt.Sprintf("%s(%s)", tu.Name, string(tu.Input)))
			out, rerr := tp.Run(ctx, tu.Name, tu.Input)
			if rerr != nil {
				block.Content = "tool error: " + rerr.Error()
				block.IsError = true
			} else {
				block.Content = out
			}
			results = append(results, block)
		}
		messages = append(messages, anthMsg{Role: "user", Content: results})
	}
}

// overBudget returns a reason when the i-th call of a round, after totalCalls
// already made, exceeds the per-round or total tool budget; "" otherwise.
func overBudget(i, totalCalls, maxIter int) string {
	if i >= maxToolCallsPerRound {
		return fmt.Sprintf("at most %d tool calls per round; this call was not executed", maxToolCallsPerRound)
	}
	if totalCalls >= maxIter*maxToolCallsPerRound {
		return "total tool budget for this run is exhausted; conclude with the evidence you have"
	}
	return ""
}

func (p *anthropicProvider) call(ctx context.Context, req anthReq) (*anthResp, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	resp, err := doWithRetry(ctx, p.httpc, func() (*http.Request, error) {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("content-type", "application/json")
		httpReq.Header.Set("x-api-key", p.apiKey)
		httpReq.Header.Set("anthropic-version", anthropicVersion)
		return httpReq, nil
	})
	if err != nil {
		return nil, fmt.Errorf("call anthropic api: %w", err)
	}
	defer resp.Body.Close()

	var ar anthResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&ar); err != nil {
		return nil, fmt.Errorf("decode api response (status %d): %w", resp.StatusCode, err)
	}
	if ar.Error != nil {
		return nil, fmt.Errorf("anthropic api error: %s: %s", ar.Error.Type, ar.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anthropic api returned status %d", resp.StatusCode)
	}
	return &ar, nil
}
