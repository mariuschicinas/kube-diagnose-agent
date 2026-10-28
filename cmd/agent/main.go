// Command agent is a read-only Kubernetes diagnostic CLI. v0 supports one
// subcommand:
//
//	agent diagnose -n <namespace> <pod>
//	agent diagnose -n <namespace> pod/<pod> [--json] [--show-bundle]
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"kube-diagnose-agent/internal/diagnose"
	"kube-diagnose-agent/internal/llm"
	"kube-diagnose-agent/internal/sanitize"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// agentVersion is stamped into every audit record. Set via -ldflags at build
// time: -ldflags "-X main.agentVersion=$(git describe --tags --always)".
var agentVersion = "dev"

const (
	defaultTail     = 200
	maxTail         = 10000
	defaultLogBytes = 64 << 10
	maxLogBytes     = 8 << 20
	minRunTimeout   = 5 * time.Minute
	runTimeoutSlack = 30 * time.Second
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "diagnose":
		if err := runDiagnose(os.Args[2:]); err != nil {
			// Errors can embed model output or API error bodies, both derived
			// from attacker-influenceable text: sanitise before the terminal.
			fmt.Fprintf(os.Stderr, "error: %s\n", sanitize.Terminal(err.Error()))
			os.Exit(1)
		}
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `agent — read-only Kubernetes diagnostic agent

Usage:
  agent diagnose -n <namespace> <pod> [flags]

Flags:
  -n, --namespace       namespace of the pod (required)
      --kubeconfig      path to kubeconfig (precedence: flag, in-cluster, $KUBECONFIG, ~/.kube/config)
      --provider        LLM backend: anthropic | openai-compat (default: anthropic)
      --model           model name (default: `+llm.DefaultAnthropicModel+` for anthropic)
      --base-url        endpoint for openai-compat, e.g. http://localhost:11434/v1
      --api-key-env     env var holding the API key (default ANTHROPIC_API_KEY)
      --tail            log lines per container instance (default: 200, max 10000)
      --log-bytes       max bytes per container instance log (default: 65536)
      --max-tokens      model output token budget (default: 2048)
      --max-iterations  max read-only tool-call rounds (default: 4; 0 = no tools)
      --json            emit {"result": ..., "tool_trace": [...]} instead of a human report
      --show-bundle     print the redacted bundle that was sent to the model
      --audit-log       append a JSON-Lines audit record for this run to the given file
      --audit-required  fail the run if the audit record cannot be written

Environment:
  ANTHROPIC_API_KEY   required for --provider=anthropic

Self-hosted / alternative backends (agent operates no inference service; it is
only an HTTP client, and the security boundaries are unchanged):

  Ollama   agent diagnose -n demo crashloop \
             --provider openai-compat --base-url http://localhost:11434/v1 \
             --model qwen2.5:14b

  vLLM     agent diagnose -n demo crashloop \
             --provider openai-compat --base-url http://vllm.internal:8000/v1 \
             --model Qwen/Qwen2.5-14B-Instruct

  LiteLLM  (proxy to Bedrock / Azure / etc)
           agent diagnose -n demo crashloop \
             --provider openai-compat --base-url http://litellm.internal:4000/v1 \
             --model bedrock/anthropic.claude-3-5-sonnet --api-key-env LITELLM_KEY
`)
}

func runDiagnose(args []string) error {
	fs := flag.NewFlagSet("diagnose", flag.ExitOnError)
	var ns, kubeconfig, model, provider, baseURL, apiKeyEnv string
	var tail, logBytes int64
	var maxTokens, maxIterations int
	var asJSON, showBundle, auditRequired bool
	var auditLog string

	fs.StringVar(&ns, "n", "", "namespace")
	fs.StringVar(&ns, "namespace", "", "namespace")
	fs.StringVar(&kubeconfig, "kubeconfig", "", "path to kubeconfig")
	fs.StringVar(&provider, "provider", "anthropic", "LLM backend: anthropic | openai-compat")
	fs.StringVar(&model, "model", "", "model name (defaults per provider)")
	fs.StringVar(&baseURL, "base-url", "", "endpoint for openai-compat (e.g. http://localhost:11434/v1)")
	fs.StringVar(&apiKeyEnv, "api-key-env", "", "env var holding the API key (default ANTHROPIC_API_KEY; may be empty for local backends)")
	fs.Int64Var(&tail, "tail", defaultTail, "log lines per container instance")
	fs.Int64Var(&logBytes, "log-bytes", defaultLogBytes, "max bytes per container instance log")
	fs.IntVar(&maxTokens, "max-tokens", 2048, "model output token budget")
	fs.IntVar(&maxIterations, "max-iterations", 4, "max read-only tool-call rounds the agent may take (0 = single-shot, no tools)")
	fs.BoolVar(&asJSON, "json", false, "emit raw JSON")
	fs.BoolVar(&showBundle, "show-bundle", false, "print the redacted bundle sent to the model")
	fs.StringVar(&auditLog, "audit-log", "", "append a JSON-Lines audit record for this run to the given file")
	fs.BoolVar(&auditRequired, "audit-required", false, "fail the run if the audit record cannot be written")
	// The flag package stops parsing at the first positional argument, so any
	// flag placed after the pod name (e.g. `-n demo crashloop --show-bundle`)
	// would be silently dropped. Parse in a loop so flags work in any position.
	var positional []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}

	if ns == "" {
		return fmt.Errorf("namespace is required (-n)")
	}
	if len(positional) != 1 {
		return fmt.Errorf("exactly one pod argument is required")
	}
	pod := strings.TrimPrefix(positional[0], "pod/")
	switch {
	case maxIterations < 0:
		return fmt.Errorf("--max-iterations must be >= 0")
	case tail < 1 || tail > maxTail:
		return fmt.Errorf("--tail must be between 1 and %d", maxTail)
	case logBytes < 1 || logBytes > maxLogBytes:
		return fmt.Errorf("--log-bytes must be between 1 and %d", maxLogBytes)
	case maxTokens < 1:
		return fmt.Errorf("--max-tokens must be >= 1")
	}

	cs, err := newClientset(kubeconfig)
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}

	// One call per round plus the forced-conclusion round, each bounded by
	// llm.CallTimeout; the run deadline must be at least that or a slow
	// self-hosted model is cancelled mid-investigation.
	timeout := time.Duration(maxIterations+1)*llm.CallTimeout + runTimeoutSlack
	if timeout < minRunTimeout {
		timeout = minRunTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var auditWriter io.Writer
	if auditLog != "" {
		f, ferr := os.OpenFile(auditLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if ferr != nil {
			return fmt.Errorf("open audit log: %w", ferr)
		}
		defer f.Close()
		// 0o600 above only applies when the file is created; tighten an
		// existing one too (a device like /dev/stdout may refuse — fine).
		if cerr := f.Chmod(0o600); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: audit log %s: could not set mode 0600: %v\n", auditLog, cerr)
		}
		auditWriter = f
	}

	rep, err := diagnose.Run(ctx, cs, diagnose.Options{
		Namespace:     ns,
		Pod:           pod,
		Tail:          tail,
		MaxLogBytes:   logBytes,
		Provider:      provider,
		Model:         model,
		BaseURL:       baseURL,
		APIKeyEnv:     apiKeyEnv,
		MaxTokens:     maxTokens,
		MaxIterations: maxIterations,
		AgentVersion:  agentVersion,
		Initiator:     osUser(),
		AuditWriter:   auditWriter,
	})
	if showBundle && rep.Bundle != "" {
		// The bundle contains raw container logs. A log line carrying an ANSI
		// escape (clear screen, OSC 52 clipboard write) must not run here.
		fmt.Fprintf(os.Stderr, "--- redacted bundle sent to model ---\n%s\n--- end bundle ---\n", sanitize.Terminal(rep.Bundle))
	}
	// Refusals are a tampering signal: show them whether or not the run
	// succeeded (on success they are also in the RCA notes).
	if len(rep.Denied) > 0 {
		fmt.Fprintf(os.Stderr, "%s\n", sanitize.Terminal(diagnose.DeniedWarning(ns, rep.Denied)))
	}
	if rep.AuditErr != nil {
		if auditRequired {
			return fmt.Errorf("audit record could not be written (--audit-required): %w", rep.AuditErr)
		}
		fmt.Fprintf(os.Stderr, "warning: audit record could not be written: %v\n", rep.AuditErr)
	}
	if err != nil {
		return err
	}

	if asJSON {
		return diagnose.RenderJSON(os.Stdout, rep.Result, rep.Trace)
	}
	diagnose.RenderText(os.Stdout, ns, pod, rep.Result, rep.Trace)
	return nil
}

// newClientset resolves the cluster config in this order: an explicit
// --kubeconfig flag, in-cluster config, $KUBECONFIG, ~/.kube/config. An explicit
// flag always wins — it must never be silently overridden by the environment the
// binary happens to run in.
func newClientset(kubeconfig string) (kubernetes.Interface, error) {
	if kubeconfig == "" {
		if cfg, err := rest.InClusterConfig(); err == nil {
			return kubernetes.NewForConfig(cfg)
		}
		if env := os.Getenv("KUBECONFIG"); env != "" {
			kubeconfig = env
		} else if home, _ := os.UserHomeDir(); home != "" {
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

// osUser returns the OS username that launched the agent, for the audit record.
func osUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}
