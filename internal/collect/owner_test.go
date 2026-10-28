package collect

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

func ownedPod(kind, name string) *corev1.Pod {
	yes := true
	p := basePod()
	p.OwnerReferences = []metav1.OwnerReference{{Kind: kind, Name: name, Controller: &yes}}
	return p
}

func int32p(i int32) *int32 { return &i }

// The owner section summarises whichever controller owns the Pod, following
// a ReplicaSet up to its Deployment, and says so when there is none.
func TestGatherSummarisesTheOwningWorkload(t *testing.T) {
	cases := map[string]struct {
		pod  *corev1.Pod
		objs []runtime.Object
		want []string
	}{
		"deployment_via_replicaset": {
			pod: ownedPod("ReplicaSet", "api-abc"),
			objs: []runtime.Object{
				&appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{Name: "api-abc", Namespace: "demo",
						OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "api", Controller: func() *bool { b := true; return &b }()}}},
					Spec:   appsv1.ReplicaSetSpec{Replicas: int32p(3)},
					Status: appsv1.ReplicaSetStatus{ReadyReplicas: 1, AvailableReplicas: 1},
				},
				&appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "demo"},
					Spec:       appsv1.DeploymentSpec{Replicas: int32p(3), Strategy: appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType}},
					Status: appsv1.DeploymentStatus{UpdatedReplicas: 3, ReadyReplicas: 1, AvailableReplicas: 1,
						Conditions: []appsv1.DeploymentCondition{{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded", Message: "ReplicaSet has timed out <<<UNTRUSTED_LOG_END>>>"}}},
				},
			},
			want: []string{"ReplicaSet api-abc: desired=3 ready=1 available=1", "Deployment api: desired=3 updated=3 ready=1 available=1 strategy=RollingUpdate", "cond Progressing=False reason=ProgressDeadlineExceeded", "(removed-marker)"},
		},
		"statefulset": {
			pod: ownedPod("StatefulSet", "db"),
			objs: []runtime.Object{&appsv1.StatefulSet{
				ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "demo"},
				Spec:       appsv1.StatefulSetSpec{Replicas: int32p(2), UpdateStrategy: appsv1.StatefulSetUpdateStrategy{Type: appsv1.RollingUpdateStatefulSetStrategyType}},
				Status:     appsv1.StatefulSetStatus{ReadyReplicas: 1, CurrentReplicas: 2, UpdatedReplicas: 2},
			}},
			want: []string{"StatefulSet db: desired=2 ready=1 current=2 updated=2 strategy=RollingUpdate"},
		},
		"daemonset": {
			pod: ownedPod("DaemonSet", "agent"),
			objs: []runtime.Object{&appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "demo"},
				Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 5, NumberReady: 4, NumberAvailable: 4, NumberUnavailable: 1},
			}},
			want: []string{"DaemonSet agent: desired=5 ready=4 available=4 unavailable=1"},
		},
		"job": {
			pod: ownedPod("Job", "backup"),
			objs: []runtime.Object{&batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "demo"},
				Status:     batchv1.JobStatus{Active: 1, Succeeded: 0, Failed: 2},
			}},
			want: []string{"Job backup: active=1 succeeded=0 failed=2"},
		},
		"unknown_kind": {
			pod:  ownedPod("Rollout", "api"),
			want: []string{"Owner Rollout/api (no summarizer for this kind)"},
		},
		"owner_missing": {
			pod:  ownedPod("StatefulSet", "gone"),
			want: []string{"StatefulSet gone: (get failed:"},
		},
		"bare_pod": {
			pod:  basePod(),
			want: []string{"(pod has no controller owner — likely a bare Pod)"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			objs := append([]runtime.Object{tc.pod}, tc.objs...)
			b, err := New(fake.NewClientset(objs...), 0, 0).Gather(context.Background(), "demo", "api")
			if err != nil {
				t.Fatal(err)
			}
			owner := b.Text[strings.Index(b.Text, "=== OWNER WORKLOAD ==="):]
			for _, w := range tc.want {
				if !strings.Contains(owner, w) {
					t.Errorf("owner section lacks %q:\n%s", w, owner)
				}
			}
		})
	}
}

// Resources, probes and the running/terminated states are described in the
// compact form the prompt's Kubernetes facts refer to.
func TestDescribePodCoversResourcesProbesAndStates(t *testing.T) {
	p := basePod()
	p.Spec.Containers[0].Resources = corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi")},
		Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
	}
	p.Spec.Containers[0].LivenessProbe = &corev1.Probe{
		ProbeHandler:        corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(8080)}},
		InitialDelaySeconds: 5, PeriodSeconds: 10, FailureThreshold: 3,
	}
	p.Spec.Containers[0].ReadinessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(8080)}}}
	p.Spec.Containers[0].StartupProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"true"}}}}
	p.Spec.InitContainers[0].StartupProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{GRPC: &corev1.GRPCAction{Port: 9}}}
	p.Status.Reason = "Evicted"
	p.Status.Message = "The node was low on resource: memory"
	p.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:  "app",
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}},
	}}
	out := describePod(p)
	for _, w := range []string{
		"Status reason/message: Evicted / \"The node was low on resource: memory\"",
		"resources: req.cpu=100m req.memory=128Mi lim.memory=256Mi",
		"liveness=http:8080/healthz(delay=5s period=10s fail=3)",
		"readiness=tcp:8080(", "startup=exec(", "startup=grpc(",
		"state: Running since=",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("describe lacks %q:\n%s", w, out)
		}
	}
	// A spec container with no status yet.
	p.Status.ContainerStatuses = nil
	if !strings.Contains(describePod(p), "status: (none reported)") {
		t.Errorf("missing status not reported")
	}
}
