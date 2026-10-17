package redact

import (
	"strings"
	"testing"
)

// Each secret must be redacted. Keyed by a label for readable failures.
//
// The token values below are deliberately NON-secrets: every one embeds
// "EXAMPLE"/"FAKE" and low-entropy filler. They keep the prefix and length the
// redaction regexes key on (so they exercise the real patterns), but they are
// not valid credentials and must not be treated as such by secret scanners.
func TestScrubRedactsSecrets(t *testing.T) {
	cases := map[string]string{
		"aws_key_id":     "AKIAEXAMPLEFAKEKEY00",
		"aws_temp_creds": "ASIAEXAMPLEFAKEKEY00",
		"gcp_api_key":    "AIzaEXAMPLE-FAKE-GCP-API-KEY-00000000000",
		"google_oauth":   "ya29.EXAMPLE-FAKE-GOOGLE-OAUTH-TOKEN-0000",
		"azure_conn":     "DefaultEndpoint;AccountKey=EXAMPLE-FAKE-AZURE-KEY==;Other=1",
		"github_classic": "ghp_EXAMPLEFAKEGITHUBTOKENexample0000000000",
		"github_fine":    "github_pat_EXAMPLE_FAKE_FINEGRAINED_TOKEN_0000",
		"gitlab_pat":     "glpat-EXAMPLE-FAKE-GITLAB-TOKEN-00",
		"npm_token":      "npm_EXAMPLEFAKENPMTOKENexample0000000000",
		"slack_token":    "xoxb-EXAMPLE-FAKE-SLACK-TOKEN-000",
		"slack_webhook":  "https://hooks.slack.com/services/EXAMPLE/FAKE/WEBHOOKTOKEN",
		"anthropic_key":  "sk-ant-EXAMPLE-FAKE-ANTHROPIC-KEY-00",
		"openai_key":     "sk-proj-EXAMPLEFAKEOPENAIKEY00000000",
		"jwt":            "eyJhbGciOiJIUzI1NiJ9.eyJFWEFNUExFIjoiRkFLRSJ9.ZXhhbXBsZWZha2U",
		"bearer":         "Authorization: Bearer EXAMPLE-fake-token-000",
		"url_creds":      "postgres://app:EXAMPLEfakePW@db:5432/mydb",
		"sensitive_kv":   `password="EXAMPLE-fake-password"`,
		"email":          "oncall@example.com",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			out := Scrub(in)
			if out == in {
				t.Fatalf("not redacted: %q stayed unchanged", in)
			}
			if !strings.Contains(out, "REDACTED") {
				t.Fatalf("no REDACTED placeholder in output: %q -> %q", in, out)
			}
			// The literal secret value must not survive verbatim. For labelled
			// forms (bearer/kv/url/azure) only the value is masked, so check the
			// high-entropy tail rather than the whole string.
			if strings.Contains(out, "EXAMPLE-fake-password") ||
				strings.Contains(out, "EXAMPLEfakePW") {
				t.Fatalf("secret value leaked through: %q", out)
			}
		})
	}
}

// Ordinary Kubernetes log/status text must pass through untouched — a redactor
// that mangles normal output trains people to distrust it.
func TestScrubLeavesBenignTextUntouched(t *testing.T) {
	benign := []string{
		"Phase: Running restartCount=7 exitCode=137",
		"back-off 5m0s restarting failed container=app",
		"image=busybox:1.36 memory limit 256Mi",
		"dial tcp 10.244.0.12:9999: connect: connection refused",
		"Successfully pulled image in 662ms (3.057s)",
		"lastState: Terminated reason=OOMKilled exitCode=137",
	}
	for _, b := range benign {
		if out := Scrub(b); out != b {
			t.Errorf("false positive: %q was modified to %q", b, out)
		}
	}
}
