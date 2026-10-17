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

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// agentVersion is stamped into every audit record. Set via -ldflags at build
// time: -ldflags "-X main.agentVersion=$(git describe --tags --always)".
var agentVersion = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "diagnose":
		if err := runDiagnose(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
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
  -n, --namespace   namespace of the pod (required)
      --kubeconfig      path to kubeconfig (default: in-cluster, then $KUBECONFIG, then ~/.kube/config)
      --provider        LLM backend: anthropic | openai-compat (default: anthropic)
      --model           model name (default: `+llm.DefaultAnthropicModel+` for anthropic)
      --base-url        endpoint for openai-compat, e.g. http://localhost:11434/v1
      --api-key-env     env var holding the API key (default ANTHROPIC_API_KEY)
      --tail            log lines per container instance (default: 200)
      --max-tokens      model output token budget (default: 2048)
      --max-iterations  max read-only tool-call rounds (default: 4; 0 = no tools)
      --json            emit raw JSON instead of a human report
      --show-bundle print the redacted bundle that was sent to the model

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
	var tail int64
	var maxTokens, maxIterations int
	var asJSON, showBundle bool
	var auditLog string

	fs.StringVar(&ns, "n", "", "namespace")
	fs.StringVar(&ns, "namespace", "", "namespace")
	fs.StringVar(&kubeconfig, "kubeconfig", "", "path to kubeconfig")
	fs.StringVar(&provider, "provider", "anthropic", "LLM backend: anthropic | openai-compat")
	fs.StringVar(&model, "model", "", "model name (defaults per provider)")
	fs.StringVar(&baseURL, "base-url", "", "endpoint for openai-compat (e.g. http://localhost:11434/v1)")
	fs.StringVar(&apiKeyEnv, "api-key-env", "", "env var holding the API key (default ANTHROPIC_API_KEY; may be empty for local backends)")
	fs.Int64Var(&tail, "tail", 200, "log lines per container instance")
	fs.IntVar(&maxTokens, "max-tokens", 2048, "model output token budget")
	fs.IntVar(&maxIterations, "max-iterations", 4, "max read-only tool-call rounds the agent may take (0 = single-shot, no tools)")
	fs.BoolVar(&asJSON, "json", false, "emit raw JSON")
	fs.BoolVar(&showBundle, "show-bundle", false, "print the redacted bundle sent to the model")
	fs.StringVar(&auditLog, "audit-log", "", "append a JSON-Lines audit record for this run to the given file")
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

	cs, err := newClientset(kubeconfig)
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var auditWriter io.Writer
	if auditLog != "" {
		f, ferr := os.OpenFile(auditLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if ferr != nil {
			return fmt.Errorf("open audit log: %w", ferr)
		}
		defer f.Close()
		auditWriter = f
	}

	res, bundle, trace, err := diagnose.Run(ctx, cs, diagnose.Options{
		Namespace:     ns,
		Pod:           pod,
		Tail:          tail,
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
	if showBundle {
		fmt.Fprintf(os.Stderr, "--- redacted bundle sent to model ---\n%s\n--- end bundle ---\n", bundle)
	}
	if err != nil {
		return err
	}

	if asJSON {
		return diagnose.RenderJSON(os.Stdout, res)
	}
	diagnose.RenderText(os.Stdout, ns, pod, res, trace)
	return nil
}

// newClientset prefers in-cluster config, then an explicit/standard kubeconfig.
func newClientset(kubeconfig string) (kubernetes.Interface, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return kubernetes.NewForConfig(cfg)
	}
	if kubeconfig == "" {
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
