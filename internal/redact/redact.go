// Package redact removes likely secrets and PII from the diagnostic bundle
// BEFORE it is sent to an external LLM. It is a fixed choke point that every byte
// passes through on the way out — the architectural point, not an afterthought.
//
// The ruleset keys off distinctive prefixes (provider tokens) and on the common
// ways credentials are spelled in logs and config dumps: env-style
// DB_PASSWORD=, YAML/JSON "password": "...", connection strings (Pwd=), CLI
// flags (--password x), Authorization headers, cookies. A crashing app that
// prints its environment or config is the typical leak, so those shapes must be
// covered even at the cost of the occasional over-redaction of a harmless
// "token_ttl=3600".
//
// It is still NOT exhaustive: a high-entropy secret with no recognisable shape
// (many Azure AD client secrets, a bespoke token) can slip through. Redaction is
// best-effort defence in depth, not a guarantee; the hard boundaries are RBAC
// and the namespace allowlist. Run with --show-bundle to see exactly what the
// model would receive, and extend these patterns for your environment.
//
// Scrub is applied per section while the bundle is assembled (so no rule can
// span from one section into another and swallow structure such as the
// untrusted-log fence) and once more on the whole bundle as a second pass.
package redact

import "regexp"

type rule struct {
	re   *regexp.Regexp
	repl string
}

// sensitiveKey matches an identifier that contains a secret-ish word. The word
// must end the identifier or be followed by a separator, so DB_PASSWORD,
// POSTGRES_PASSWORD, aws_secret_access_key, Pwd, api-key and token_ttl match,
// while max_tokens or tokenizer do not.
const sensitiveKey = `(?i)([A-Za-z0-9_.-]*?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?)(?:[_.-][A-Za-z0-9_.-]*)?)`

// rules are applied in order. Provider-specific patterns run before the generic
// key=value catch-all so the more precise placeholder wins.
var rules = []rule{
	// --- structural / cross-provider ---
	// Private key blocks (PEM) — covers RSA, EC, OPENSSH, and GCP SA keys. The
	// body is restricted to base64 + line breaks (no spaces, no punctuation),
	// so a BEGIN line in one place and an END line far away can never swallow
	// the prose — or the bundle structure — in between.
	{regexp.MustCompile(`-----BEGIN [^-\n]{0,40}PRIVATE KEY-----[A-Za-z0-9+/=\r\n]*-----END [^-\n]{0,40}PRIVATE KEY-----`), "[REDACTED_PRIVATE_KEY]"},
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

	// --- LLM provider keys (a crashing app may print its own key in a log line) ---
	// Anthropic (sk-ant-...) and OpenAI (sk-..., sk-proj-..., sk-svcacct-...).
	// Real keys contain '-' and '_', so the charset must include them.
	{regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`), "[REDACTED_LLM_KEY]"},

	// --- generic ---
	// Authorization headers / log echoes: Bearer and Basic. The charset covers
	// base64 (+ / =) so the tail of a token cannot survive. The minimum length
	// keeps prose like "the bearer of" intact.
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`), "${1} [REDACTED_TOKEN]"},
	// Cookie headers carry session tokens.
	{regexp.MustCompile(`(?i)\b(cookie|set-cookie):[ \t]*[^\r\n]+`), "${1}: [REDACTED]"},
	// Credentials embedded in URLs: scheme://user:pass@host -> mask the password.
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://[^:/\s@]+:)([^@/\s]+)(@)`), "${1}[REDACTED]${3}"},
	// key=value / key: "value" where the key name looks sensitive. Three
	// spellings of the value — double-quoted, single-quoted, bare — so a value
	// containing ',' or ' ' inside quotes is masked whole, and the quotes are
	// kept so the surrounding JSON/YAML stays readable.
	{regexp.MustCompile(sensitiveKey + `(\s*["']?\s*[:=]\s*")([^"]*)(")`), "${1}${2}[REDACTED]${4}"},
	{regexp.MustCompile(sensitiveKey + `(\s*["']?\s*[:=]\s*')([^']*)(')`), "${1}${2}[REDACTED]${4}"},
	{regexp.MustCompile(sensitiveKey + `(\s*["']?\s*[:=]\s*)([^\s"',;}&]+)`), "${1}${2}[REDACTED]"},
	// CLI flags with a space-separated value: --password hunter2, -token x.
	{regexp.MustCompile(`(?i)(--?(?:password|passwd|pwd|token|api-?key|secret|client-secret) +)([^\s"']+)`), "${1}[REDACTED]"},
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
