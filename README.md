# kube-diagnose-agent

![security](https://github.com/mariuschicinas/kube-diagnose-agent/actions/workflows/security.yml/badge.svg)
![license](https://img.shields.io/badge/license-Apache%202.0-blue)

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
   list / pods/log). The supported way to run the agent is **in-cluster, as
   the `diagnose-agent` ServiceAccount** ([`deploy/job.yaml`](deploy/job.yaml)),
   whose role grants exactly the verbs the code calls and nothing else. Only
   then is read-only an RBAC boundary rather than a code convention: a
   compromised process holds a token that cannot write, exec or read Secrets.
   Two RBAC manifests ship:
   [`deploy/rbac-namespaced.yaml`](deploy/rbac-namespaced.yaml) (recommended —
   one RoleBinding per namespace the agent may diagnose, so the token itself
   cannot read anywhere else) and [`deploy/rbac.yaml`](deploy/rbac.yaml)
   (cluster-wide read, for clusters where every namespace is in scope). CI
   parses both and fails on any verb outside get/list/watch, any wildcard, any
   dangerous resource (`secrets`, `pods/exec`), and on drift against the
   resources the code actually reads.

   Running from a laptop with `--kubeconfig` is for development only, and the
   agent says so at start-up: in that mode the process holds whatever rights
   your kubeconfig user has, and read-only is enforced by this code alone.
   There is no silent fallback to `~/.kube/config`.

2. **Redaction is a fixed choke point.** Every section of the bundle passes
   through [`internal/redact`](internal/redact/redact.go) before it leaves the
   process: private keys, JWTs, cloud credentials (AWS, GCP, Azure),
   source-control and CI tokens (GitHub, GitLab, npm), Slack tokens, LLM API
   keys, `Bearer`/`Basic`/cookie headers, URL-embedded credentials, and the
   usual credential spellings a crashing app dumps (`DB_PASSWORD=`,
   `"api_key": "..."`, `Pwd=` in connection strings, `--password x`), plus
   emails. Redaction is **best-effort defence in depth**, not a guarantee: a
   high-entropy secret with no recognisable shape can still pass. The hard
   boundaries are RBAC and the namespace allowlist. Run with `--show-bundle`
   to see exactly what was sent, and extend the rules for your environment.

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
recent Events (newest 50, with full timestamps), current **and
previous-instance** logs of every container — init containers and native
sidecars, app containers, ephemeral debug containers (the previous instance is
where CrashLoopBackOff hides; the init container is where
`Init:CrashLoopBackOff` hides) — each bounded by `--tail` lines and
`--log-bytes` bytes, and a summary of the owning workload (Deployment /
ReplicaSet / StatefulSet / DaemonSet / Job). Free-text fields written by the
application (termination messages, condition messages, event text) are
bounded and neutralised like log lines.

## Setup

### In-cluster (supported)

The agent runs as a one-off Job under the `diagnose-agent` ServiceAccount.
An operator starts it; nothing runs on its own.

```bash
# 1. RBAC: pick ONE of the two manifests (see "Why it's built this way").
kubectl apply -f deploy/rbac-namespaced.yaml   # edit the RoleBinding namespace first

# 2. LLM credential, in the agent's namespace.
kubectl -n diagnostics create secret generic diagnose-agent-llm \
  --from-literal=ANTHROPIC_API_KEY=sk-ant-...

# 3. Image. Distroless, non-root, built from the committed vendor/ tree.
make image IMG=<registry>/kube-diagnose-agent:<tag> && docker push <registry>/kube-diagnose-agent:<tag>
#    then set .spec.template.spec.containers[0].image in deploy/job.yaml (by digest in production)

# 4. One diagnosis = one Job.
sed 's/__NS__/prod/g; s/__POD__/api-7d9f-abc/g' deploy/job.yaml | kubectl create -f -
kubectl -n diagnostics logs -f job/diagnose-api-7d9f-abc
```

The report and the JSON-Lines audit record are both written to the Job's
stdout, so they land in the cluster's log pipeline together. Confirm the
boundary yourself at any time:

```bash
kubectl auth can-i delete pods --as=system:serviceaccount:diagnostics:diagnose-agent -n prod   # no
kubectl auth can-i get secrets --as=system:serviceaccount:diagnostics:diagnose-agent -n prod   # no
```

### On a laptop (development only)

Requires Go 1.26+ (the version pinned in `go.mod`; `go` downloads it
automatically if your local toolchain is older). The vendored dependencies
are committed, so no `go mod tidy` is needed.

```bash
make build                       # -> bin/agent
export ANTHROPIC_API_KEY=sk-ant-...
./bin/agent diagnose -n demo crashloop --kubeconfig ~/.kube/config
```

`--kubeconfig` must be explicit, and the agent prints a warning naming the
context and user: in this mode RBAC does not bound the process. `make run
NS=demo POD=crashloop` does the same.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `-n`, `--namespace` | — | namespace of the Pod (required) |
| `--kubeconfig` | — | development only; otherwise in-cluster |
| `--provider` | `anthropic` | `anthropic` or `openai-compat` |
| `--model` | per provider | model name |
| `--base-url` | — | endpoint for `openai-compat` |
| `--api-key-env` | `ANTHROPIC_API_KEY` | env var holding the API key; may be unset for local backends |
| `--tail` | 200 | log lines per container instance (max 10000) |
| `--log-bytes` | 65536 | bytes per container instance log |
| `--max-tokens` | 2048 | model output budget |
| `--max-iterations` | 4 | read-only tool rounds; `0` = single-shot, no tools |
| `--json` | off | emit `{"result": …, "tool_trace": […]}` |
| `--show-bundle` | off | print the redacted bundle that was sent (sanitised for the terminal) |
| `--audit-log` | — | append one JSON-Lines audit record per run to this file |
| `--audit-required` | off | fail the run if the audit record cannot be written |

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

This is observed, not hypothetical: on the `injection-naive` scenario, a
self-hosted Qwen2.5-14B-Instruct (vLLM) followed the injected instruction and
called `get_pod` on `kube-system/vault-0`. The allowlist refused the call, the
report flagged it as likely prompt injection, and the refusal is in the audit
log. Claude, on the same bundle, ignored the payload and made no tool calls.

## Roadmap

- **v1 — tool-use loop.** ✅ Done. Read-only tools (`get_service`,
  `get_endpoints`, `get_pod`) with a hard iteration cap; tool calls traced.
- **next — more read-only tools.** Optional Prometheus query tool; `list_pods`
  by selector; dependency-Pod logs — each added only when a failure mode needs
  it.
- **done — audit trail and self-hosted inference.** Every run can write a
  structured JSON audit record (`--audit-log`): resolved model and endpoint,
  prompt and bundle digests, every tool call, refusals, and the outcome — on
  failed runs too. The `openai-compat` backend has been run end to end
  against vLLM.

## How this was built

This project was built with substantial AI assistance: most of the code was
written in pair-programming sessions with Claude (Anthropic). The problem
framing, security requirements and design decisions, testing against real
clusters, and review of every change are mine. Findings from an independent
security review were fixed through the same process.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
