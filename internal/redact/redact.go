// Package redact removes likely secrets and PII from the diagnostic bundle
// BEFORE it is sent to an external LLM. It is a fixed choke point that every byte
// passes through on the way out — the architectural point, not an afterthought.
//
// The ruleset is high-precision by design: every pattern keys off a distinctive
// prefix or structure, so false positives are rare. That is deliberate — a
// redactor that mangles ordinary log text trains people to distrust it. It is
// therefore also NOT exhaustive: a high-entropy secret with no recognisable
// shape (many Azure AD client secrets, a bespoke token) can still slip through.
// Redaction is defence in depth, not a guarantee; the hard boundaries are RBAC
// and the namespace allowlist. Run with --show-bundle to see exactly what the
// model would receive, and extend these patterns for your environment.
package redact

import "regexp"

type rule struct {
	re   *regexp.Regexp
	repl string
}

// rules are applied in order. Provider-specific patterns run before the generic
// key=value catch-all so the more precise placeholder wins.
var rules = []rule{
	// --- structural / cross-provider ---
	// Private key blocks (PEM) — covers RSA, EC, OPENSSH, and GCP SA keys.
	{regexp.MustCompile(`(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`), "[REDACTED_PRIVATE_KEY]"},
	// JWTs (header.payload.signature, base64url).
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}`), "[REDACTED_JWT]"},

	// --- cloud providers ---
	// AWS access key IDs (also AKIA/ASIA/AGPA/AIDA/AROA... — the distinctive 4+16).
	{regexp.MustCompile(`A(KIA|SIA|GPA|IDA|ROA|IPA|NPA|NVA)[0-9A-Z]{16}`), "[REDACTED_AWS_KEY_ID]"},
	// GCP API keys.
	{regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`), "[REDACTED_GCP_API_KEY]"},
	// Google OAuth access tokens.
	{regexp.MustCompile(`ya29\.[0-9A-Za-z_\-]{20,}`), "[REDACTED_GOOGLE_OAUTH]"},
	// Azure storage / SAS keys inside connection strings.
	{regexp.MustCompile(`(?i)(AccountKey|SharedAccessKey|SharedSecretValue)=[^;\s"']+`), "${1}=[REDACTED]"},

	// --- source control / CI / registries ---
	// GitHub tokens (classic ghp_/gho_/ghu_/ghs_/ghr_ and fine-grained PATs).
	{regexp.MustCompile(`(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[0-9A-Za-z_]{22,})`), "[REDACTED_GITHUB_TOKEN]"},
	// GitLab personal access tokens.
	{regexp.MustCompile(`glpat-[0-9A-Za-z_\-]{20,}`), "[REDACTED_GITLAB_TOKEN]"},
	// npm access tokens.
	{regexp.MustCompile(`npm_[A-Za-z0-9]{36}`), "[REDACTED_NPM_TOKEN]"},

	// --- messaging ---
	// Slack tokens and incoming-webhook URLs.
	{regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`), "[REDACTED_SLACK_TOKEN]"},
	{regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+`), "[REDACTED_SLACK_WEBHOOK]"},

	// --- LLM provider keys (the agent reads pod env; a pod may carry one) ---
	// Anthropic (checked before the broader OpenAI rule).
	{regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`), "[REDACTED_LLM_KEY]"},
	// OpenAI (sk- and sk-proj-).
	{regexp.MustCompile(`sk-(proj-)?[A-Za-z0-9]{20,}`), "[REDACTED_LLM_KEY]"},

	// --- generic ---
	// Bearer tokens in headers / logs.
	{regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]+`), "Bearer [REDACTED_TOKEN]"},
	// Credentials embedded in URLs: scheme://user:pass@host -> mask the password.
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://[^:/\s@]+:)([^@/\s]+)(@)`), "${1}[REDACTED]${3}"},
	// key=value / key: "value" where the key name looks sensitive.
	{regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key)(["']?\s*[:=]\s*["']?)([^\s"',}]+)`), "${1}${2}[REDACTED]"},
	// Email addresses (PII).
	{regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`), "[REDACTED_EMAIL]"},
}

// Scrub returns s with all matched secret/PII material replaced by placeholders.
func Scrub(s string) string {
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}
