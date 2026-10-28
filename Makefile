BINARY  := agent
PKG     := ./cmd/agent
REPORT  := security-report.md
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMG     ?= kube-diagnose-agent:$(VERSION)

# Development only: the supported deployment is deploy/job.yaml (in-cluster).
KUBECONFIG ?= $(HOME)/.kube/config

.PHONY: build image tidy vendor run vet test clean tools scan vuln sbom report security

## --- build ---

build:
	go build -ldflags "-X main.agentVersion=$(VERSION)" -o bin/$(BINARY) $(PKG)

# Distroless, non-root, built from the vendored tree. Push it and set the
# image in deploy/job.yaml.
image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMG) .

tidy:
	go mod tidy

# Vendor the full dependency source tree into ./vendor so it can be inspected,
# committed, and scanned like any other source. Also enables offline builds.
vendor: tidy
	go mod vendor

vet:
	go vet ./...

test:
	go test ./...

# Example: make run NS=demo POD=crashloop
# Runs with your kubeconfig — RBAC does NOT bound this; see deploy/job.yaml.
run: build
	@test -n "$(NS)" || { echo "NS is required: make run NS=<namespace> POD=<pod>"; exit 2; }
	@test -n "$(POD)" || { echo "POD is required: make run NS=<namespace> POD=<pod>"; exit 2; }
	./bin/$(BINARY) diagnose -n "$(NS)" "$(POD)" --kubeconfig "$(KUBECONFIG)"

clean:
	rm -rf bin $(REPORT) sbom.json

## --- security tooling ---

# Install the scanners into $(go env GOPATH)/bin. Ensure that is on your PATH.
# Both are pinned: the gate itself must be reproducible.
tools:
	go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
	go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0

# govulncheck: Go's official scanner. Does REACHABILITY analysis — it only
# reports a CVE if the vulnerable function is actually callable from this code,
# which cuts most of the noise a generic scanner produces.
vuln:
	govulncheck ./...

# CycloneDX SBOM — the artifact a client's security team will ask for.
sbom:
	cyclonedx-gomod mod -json -output sbom.json
	@echo "wrote sbom.json"

# The authoritative gate. Manifest-level scanning was evaluated and dropped:
# it produced ~44 findings, none actionable. See section 3 of the report.
scan: vuln

# Generate the aggregated human-readable security report. Exits non-zero when
# govulncheck found reachable vulnerabilities or could not run.
report:
	./hack/security-report.sh

# One-shot: vendor, scan, SBOM, and write the report. Fails on findings.
security: vendor scan sbom report
	@echo "security pipeline complete -> $(REPORT)"
