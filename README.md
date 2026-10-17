# kube-diagnose-agent

A read-only Kubernetes diagnostic agent. Point it at a misbehaving Pod and it
produces a structured root-cause analysis: likely causes with confidence and
cited evidence, read-only next steps, and suggested remediation for a human to
review.

```
agent diagnose -n prod api-7d9f-abc
```

**Scope.** It diagnoses a single failing Pod, confirming suspected dependency
failures via read-only Service / Endpoints / Pod lookups. It does not do
cluster-wide analysis, and there is no chat or alerting interface yet — by
design, the tool surface and blast radius are kept minimal. A ChatOps entry
point ("why is the vault pod down?") and proactive alerting are on the roadmap;
both are new entry points over the same `diagnose.Run`, not changes to the core.

**v1**: the agent investigates. After assembling the initial bundle it may call
a small set of read-only tools (`get_service`, `get_endpoints`, `get_pod`) to
confirm a hypothesis before concluding — e.g. on a "cannot connect to db:5432"
crash it checks whether the `db` Service exists and has endpoints, and returns a
*confirmed* cause instead of a guess. Investigation is capped (default 4 tool
rounds) and every tool call is traced in the output. No write access, ever.

Run single-shot (v0 behaviour, no tools) with `--max-iterations 0`.

## Why it's built this way

The interesting part isn't "send logs to an LLM". It's doing that in a way you
could defend to a regulated financial-services security team. Two principles:

1. **The LLM never touches the cluster.** It only ever sees a text bundle that
   *your* code assembled. All Kubernetes access is read-only client-go (get /
   list / watch / pods/log) running under a ServiceAccount with no write verbs —
   see [`deploy/rbac.yaml`](deploy/rbac.yaml). Read-only is an RBAC boundary, not
   a code convention.

2. **Redaction is a fixed choke point.** Every byte of the bundle passes through
   [`internal/redact`](internal/redact/redact.go) before it leaves the process:
   private keys, JWTs, cloud credentials (AWS, GCP, Azure), source-control and
   CI tokens (GitHub, GitLab, npm), Slack tokens, LLM API keys, bearer tokens,
   URL-embedded credentials, secret-looking `key=value` pairs, and emails are
   masked. Run with
   `--show-bundle` to see exactly what was sent.

3. **Application logs are treated as untrusted input.** Logs and event messages
   are attacker-influenceable: anyone who can get text into an app's output can
   write into the model's context. Defences, in order of how much load they
   actually carry:

   - **Namespace allowlist (`internal/tools`) — the only hard wall.** Tool calls
     to any namespace other than the target Pod's are refused *in code*, before
     any cluster read. If the model is fully talked into reading
     `kube-system/vault-0`, it still cannot: the refusal is an `if`, not a
     judgement call. A refusal is recorded and surfaced as a SECURITY warning in
     the RCA, because an attempt is itself a tampering signal.
   - **Fence + trust boundary (probabilistic).** Logs are wrapped in explicit
     untrusted markers and the system prompt states that instructions come only
     from the system prompt — bundle content is evidence, never a command.
   - **Marker neutralization (hardening).** An attacker who has read this source
     knows the fence markers and could try to close the fence early, making the
     rest of their text look like it came from outside the untrusted block.
     `neutralize()` defangs that, along with imitation control syntax
     (`<tool_call>`, `[INST]`). Note this only matters against an attacker who
     knows the markers — the defence does **not** rely on them staying secret.

   Two test pods cover both cases: `injection` (attacker knows the markers and
   tries to escape the fence) and `injection-naive` (realistic attacker who does
   not). See [`hack/broken-pods.yaml`](hack/broken-pods.yaml).

   The honest position: only the allowlist is a guarantee. The prompt-level
   defences raise the bar, they do not close the hole. That is precisely why the
   capability surface is kept minimal — the design assumes the model *may* be
   fooled, and ensures that a fooled model still cannot do damage.

## What it collects

For the target Pod: a describe-style summary (phase, conditions, per-container
state + restart counts + **last-termination exit codes**, resources, probes),
recent Events, current **and previous-instance** container logs (the previous
instance is where CrashLoopBackOff hides), and a summary of the owning workload
(Deployment / ReplicaSet / StatefulSet / DaemonSet / Job).

## Setup

Requires Go 1.23+ and an Anthropic API key.

```bash
go mod tidy            # populate the dependency graph
make build             # -> bin/agent
export ANTHROPIC_API_KEY=sk-ant-...
./bin/agent diagnose -n prod api-7d9f-abc
```

Flags: `--json`, `--show-bundle`, `--model`, `--tail`, `--max-tokens`,
`--kubeconfig`. The client prefers in-cluster config, then `$KUBECONFIG`, then
`~/.kube/config`.

> The module is named `kube-diagnose-agent` (a local name — Go never fetches your
> own module, so this builds offline-of-itself). If you later publish it or want
> others to `go install` it, change the module path in `go.mod` to a real one
> (e.g. `github.com/you/kube-diagnose-agent`) and update the internal imports to
> match.

## LLM backends

The agent is provider-agnostic and **operates no inference service of its own** —
it is only an HTTP client. Where inference runs is an infrastructure decision for
whoever deploys it, and it does not change the agent's security posture: the
boundaries are RBAC and the namespace allowlist in code, not the choice of model.

```bash
# Hosted API (default)
agent diagnose -n demo crashloop                       # ANTHROPIC_API_KEY

# Local model, for development or an air-gapped demo
agent diagnose -n demo crashloop \
  --provider openai-compat --base-url http://localhost:11434/v1 \
  --model qwen2.5:14b                                  # Ollama

# Self-hosted in-cluster
agent diagnose -n demo crashloop \
  --provider openai-compat --base-url http://vllm.internal:8000/v1 \
  --model Qwen/Qwen2.5-14B-Instruct                    # vLLM

# In-VPC via a proxy (Bedrock, Azure OpenAI, ...)
agent diagnose -n demo crashloop \
  --provider openai-compat --base-url http://litellm.internal:4000/v1 \
  --model bedrock/anthropic.claude-3-5-sonnet --api-key-env LITELLM_KEY
```

One `openai-compat` implementation covers Ollama, vLLM, LiteLLM, and OpenAI,
because they all speak `/v1/chat/completions` with function calling.

**A caveat worth stating plainly:** smaller self-hosted models are meaningfully
worse at tool use and at resisting prompt injection than frontier models. Expect
more malformed JSON (the parser tolerates it), more speculative tool calls, and
weaker refusal behaviour. That does not weaken the security model — it is exactly
why the hard boundaries live in code. **The weaker the model, the more the
allowlist earns its keep.**

## Roadmap

- **v1 — tool-use loop.** ✅ Done. Read-only tools (`get_service`,
  `get_endpoints`, `get_pod`) with a hard iteration cap; tool calls traced.
- **next — more read-only tools.** Optional Prometheus query tool; `list_pods`
  by selector; dependency-Pod logs — each added only when a failure mode needs
  it.
- **later — compliance layer.** Persist the tool-call trace as a structured
  audit log (what was read, when), optional self-hosted inference so no log
  leaves the cluster.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
