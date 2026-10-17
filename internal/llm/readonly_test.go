package llm

import (
	"strings"
	"testing"
)

func TestNonReadOnlyCommandsAreDetected(t *testing.T) {
	blocked := []string{
		// The exact step a real run produced despite the prompt rule.
		"Confirm what port nginx is bound to, or inspect the nginx config via `kubectl exec` (read-only: review ConfigMap if one is mounted)",
		"kubectl exec -it badprobe -n demo -- ss -tlnp",
		"kubectl -n demo exec badprobe -- cat /etc/nginx/nginx.conf",
		"kubectl --context=prod -n demo attach badprobe",
		"kubectl debug node/worker-1 -it --image=busybox",
		"kubectl port-forward svc/db 5432:5432 -n demo",
		"kubectl cp demo/badprobe:/etc/nginx/nginx.conf ./nginx.conf",
		"kubectl delete pod crashloop -n demo",
		"kubectl apply -f fix.yaml",
		"kubectl patch deploy api -p '{}'",
		"kubectl scale deploy api --replicas=0",
		"kubectl rollout restart deploy/api -n demo",
		"oc exec mypod -- env",
		"KUBECTL EXEC pod -- sh",
	}
	for _, s := range blocked {
		if !nonReadOnlyCmd.MatchString(s) {
			t.Errorf("not detected as non-read-only: %q", s)
		}
	}
}

func TestReadOnlyCommandsAreKept(t *testing.T) {
	allowed := []string{
		"kubectl get events -n demo --field-selector involvedObject.name=badprobe --sort-by=.lastTimestamp",
		"kubectl describe pod badprobe -n demo",
		"kubectl logs badprobe -n demo -c web --previous",
		"kubectl -n demo get pod badprobe -o jsonpath='{.status.containerStatuses[0].lastState}'",
		"kubectl top pod -n demo",
		"kubectl auth can-i list services -n demo",
		"kubectl rollout status deploy/api -n demo",
		"kubectl rollout history deploy/api -n demo",
		"kubectl describe deployment exec-service -n demo",
		"kubectl logs api -c executor -n demo",
		"Check node-level events or kubelet logs around the restart time",
	}
	for _, s := range allowed {
		if nonReadOnlyCmd.MatchString(s) {
			t.Errorf("read-only step wrongly flagged: %q", s)
		}
	}
}

func TestEnforceReadOnlyStepsRemovesAndRecords(t *testing.T) {
	r := &Result{
		Summary: "probe misconfigured",
		RecommendedNextSteps: []string{
			"kubectl describe pod badprobe -n demo",
			"kubectl exec -it badprobe -n demo -- ss -tlnp",
			"kubectl logs badprobe -n demo",
		},
		Notes: "original note",
	}
	enforceReadOnlySteps(r)

	if len(r.RecommendedNextSteps) != 2 {
		t.Fatalf("want 2 steps kept, got %d: %v", len(r.RecommendedNextSteps), r.RecommendedNextSteps)
	}
	for _, s := range r.RecommendedNextSteps {
		if strings.Contains(s, "exec") {
			t.Fatalf("exec step survived: %q", s)
		}
	}
	if !strings.Contains(r.Notes, "Removed 1 suggested next step") || !strings.Contains(r.Notes, "original note") {
		t.Fatalf("removal not recorded in notes: %q", r.Notes)
	}
}

// End to end through the parser: a model response with an exec step comes out
// filtered.
func TestParseResultTextFiltersNonReadOnlySteps(t *testing.T) {
	text := `{"summary":"x","recommended_next_steps":["kubectl get pods -n demo","kubectl -n demo exec p -- sh"]}`
	res, err := parseResultText(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RecommendedNextSteps) != 1 || res.RecommendedNextSteps[0] != "kubectl get pods -n demo" {
		t.Fatalf("filtering not applied: %v", res.RecommendedNextSteps)
	}
}
