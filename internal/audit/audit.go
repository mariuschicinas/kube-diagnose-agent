// Package audit produces a structured, timestamped record of a single diagnose
// run. The goal is post-incident defensibility: after the fact, a reviewer must
// be able to answer "why did the agent conclude this?" — which model produced
// it, under which system prompt, which read-only calls it made, in what order,
// and what came back.
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
)

// ToolCall records one read-only tool invocation.
type ToolCall struct {
	Seq       int       `json:"seq"`
	Timestamp time.Time `json:"timestamp"`
	Tool      string    `json:"tool"`
	Input     string    `json:"input"`             // arguments as sent (already namespace-scoped)
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

	// Who/what/where.
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Provider  string `json:"provider"`
	Model     string `json:"model"`
	Initiator string `json:"initiator"` // OS user who ran the agent

	// Reproducibility anchors: identical inputs => identical hashes, without
	// retaining the sensitive inputs themselves.
	SystemPromptSHA256 string `json:"system_prompt_sha256"`
	BundleSHA256       string `json:"bundle_sha256"`

	// Investigation.
	MaxIterations int        `json:"max_iterations"`
	ToolCalls     []ToolCall `json:"tool_calls"`
	Refusals      []string   `json:"refusals,omitempty"`

	// Outcome (structured RCA is stored by the caller alongside this record;
	// here we keep only a digest so the record is self-contained but lean).
	ResultSummary        string `json:"result_summary"`
	ResultSHA256         string `json:"result_sha256"`
	InsufficientEvidence bool   `json:"insufficient_evidence"`
}

// Recorder accumulates a Record over the course of a run.
type Recorder struct {
	rec Record
	seq int
}

// New starts a recorder. agentVersion and systemPrompt are fixed for the run.
func New(agentVersion, namespace, pod, provider, model, initiator, systemPrompt string, maxIter int) *Recorder {
	return &Recorder{
		rec: Record{
			SchemaVersion:      "1",
			AgentVersion:       agentVersion,
			StartedAt:          time.Now().UTC(),
			Namespace:          namespace,
			Pod:                pod,
			Provider:           provider,
			Model:              model,
			Initiator:          initiator,
			SystemPromptSHA256: digest(systemPrompt),
			MaxIterations:      maxIter,
		},
	}
}

// SetBundle records the SHA-256 of the redacted bundle that was sent.
func (r *Recorder) SetBundle(redactedBundle string) {
	r.rec.BundleSHA256 = digest(redactedBundle)
}

// AddToolCall records one invocation. result is the (redacted) output; only its
// digest is retained. Pass refused=true and err for allowlist refusals.
func (r *Recorder) AddToolCall(tool, input, result string, refused bool, err string) {
	r.seq++
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

// Finish stamps the outcome and returns the completed record.
func (r *Recorder) Finish(summary string, insufficient bool, resultJSON string) Record {
	r.rec.FinishedAt = time.Now().UTC()
	r.rec.ResultSummary = summary
	r.rec.InsufficientEvidence = insufficient
	if resultJSON != "" {
		r.rec.ResultSHA256 = digest(resultJSON)
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
