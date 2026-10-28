// Package audit produces a structured, timestamped record of a single diagnose
// run. The goal is post-incident defensibility: after the fact, a reviewer must
// be able to answer "why did the agent conclude this?" — which model produced
// it, at which endpoint, under which system prompt, which read-only calls it
// made, in what order, what came back, and whether the run succeeded at all.
//
// The record deliberately does NOT contain the raw bundle or raw tool outputs
// (those may hold sensitive data even after redaction). It stores a SHA-256 of
// the redacted bundle so a run can be tied to its exact input without retaining
// that input, plus per-call metadata. This is an explainability trail, not a
// data lake.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"kube-diagnose-agent/internal/sanitize"
)

// maxInputBytes bounds the model-supplied tool input stored per call. The
// model is prompt-injectable; it must not be able to write arbitrary volumes
// into the audit log.
const maxInputBytes = 1024

// ToolCall records one read-only tool invocation.
type ToolCall struct {
	Seq       int       `json:"seq"`
	Timestamp time.Time `json:"timestamp"`
	Tool      string    `json:"tool"`
	Input     string    `json:"input"`             // arguments as sent (already namespace-scoped), bounded
	Refused   bool      `json:"refused,omitempty"` // true if the allowlist blocked it
	Err       string    `json:"error,omitempty"`
	// ResultDigest is a SHA-256 of the (redacted) tool result, not the result
	// itself — enough to prove what the model saw without storing it.
	ResultDigest string `json:"result_digest,omitempty"`
}

// Record is the full audit record for one run.
type Record struct {
	SchemaVersion string    `json:"schema_version"`
	AgentVersion  string    `json:"agent_version"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`

	// Who/what/where. Provider, Model and Endpoint are the values the backend
	// resolved (defaults applied), not the flags as typed.
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Provider  string `json:"provider"`
	Model     string `json:"model"`
	Endpoint  string `json:"endpoint,omitempty"`
	Initiator string `json:"initiator"` // OS user who ran the agent

	// Reproducibility anchors: identical inputs => identical hashes, without
	// retaining the sensitive inputs themselves. Two prompt digests because the
	// tool rounds use a longer system prompt than the final round.
	SystemPromptSHA256     string `json:"system_prompt_sha256"`
	ToolSystemPromptSHA256 string `json:"system_prompt_tools_sha256"`
	BundleSHA256           string `json:"bundle_sha256"`

	// Investigation.
	MaxIterations int        `json:"max_iterations"`
	ToolCalls     []ToolCall `json:"tool_calls"`
	Refusals      []string   `json:"refusals,omitempty"`

	// Outcome. "ok" or "error"; Error carries the message for a failed run so
	// a reviewer can tell "the model returned nothing" from "the run failed".
	// The structured RCA is stored by the caller alongside this record; here we
	// keep only a digest so the record is self-contained but lean.
	Outcome              string `json:"outcome"`
	Error                string `json:"error,omitempty"`
	ResultSummary        string `json:"result_summary"`
	ResultSHA256         string `json:"result_sha256"`
	InsufficientEvidence bool   `json:"insufficient_evidence"`
}

// Recorder accumulates a Record over the course of a run.
type Recorder struct {
	rec Record
	seq int
}

// New starts a recorder. It is created before anything else happens in a run
// so that a failure at any later step still leaves a record.
func New(agentVersion, namespace, pod, provider, model, initiator, systemPrompt, toolSystemPrompt string, maxIter int) *Recorder {
	return &Recorder{
		rec: Record{
			SchemaVersion:          "2",
			AgentVersion:           agentVersion,
			StartedAt:              time.Now().UTC(),
			Namespace:              namespace,
			Pod:                    pod,
			Provider:               provider,
			Model:                  model,
			Initiator:              initiator,
			SystemPromptSHA256:     digest(systemPrompt),
			ToolSystemPromptSHA256: digest(toolSystemPrompt),
			MaxIterations:          maxIter,
		},
	}
}

// SetProvider records the backend as resolved: the model actually requested
// (defaults applied) and the endpoint actually called.
func (r *Recorder) SetProvider(kind, model, endpoint string) {
	r.rec.Provider = kind
	r.rec.Model = model
	r.rec.Endpoint = endpoint
}

// SetBundle records the SHA-256 of the redacted bundle that was sent.
func (r *Recorder) SetBundle(redactedBundle string) {
	r.rec.BundleSHA256 = digest(redactedBundle)
}

// AddToolCall records one invocation. result is the (redacted) output; only its
// digest is retained. Pass refused=true and err for allowlist refusals.
func (r *Recorder) AddToolCall(tool, input, result string, refused bool, err string) {
	r.seq++
	input = sanitize.Truncate(input, maxInputBytes)
	tc := ToolCall{
		Seq:       r.seq,
		Timestamp: time.Now().UTC(),
		Tool:      tool,
		Input:     input,
		Refused:   refused,
		Err:       err,
	}
	if result != "" {
		tc.ResultDigest = digest(result)
	}
	r.rec.ToolCalls = append(r.rec.ToolCalls, tc)
	if refused {
		r.rec.Refusals = append(r.rec.Refusals, tool+"("+input+")")
	}
}

// Finish stamps the outcome and returns the completed record. runErr non-nil
// marks the run as failed; summary/resultJSON are then normally empty.
func (r *Recorder) Finish(summary string, insufficient bool, resultJSON string, runErr error) Record {
	r.rec.FinishedAt = time.Now().UTC()
	r.rec.ResultSummary = summary
	r.rec.InsufficientEvidence = insufficient
	if resultJSON != "" {
		r.rec.ResultSHA256 = digest(resultJSON)
	}
	r.rec.Outcome = "ok"
	if runErr != nil {
		r.rec.Outcome = "error"
		r.rec.Error = sanitize.Truncate(runErr.Error(), maxInputBytes)
	}
	return r.rec
}

// WriteJSON writes the record as one JSON object (newline-terminated, so files
// can be appended as JSON Lines for a running audit log).
func WriteJSON(w io.Writer, rec Record) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}
