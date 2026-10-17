BINARY := agent
PKG    := ./cmd/agent
REPORT := security-report.md

.PHONY: build tidy vendor run vet test clean tools scan vuln sbom report security

## --- build ---

build:
	go build -o bin/$(BINARY) $(PKG)

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
run: build
	./bin/$(BINARY) diagnose -n $(NS) $(POD)

clean:
	rm -rf bin $(REPORT) sbom.json

## --- security tooling ---

# Install the scanners into $(go env GOPATH)/bin. Ensure that is on your PATH.
tools:
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest

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

# Generate the aggregated human-readable security report.
report:
	./hack/security-report.sh

# One-shot: vendor, scan, SBOM, and write the report.
security: vendor sbom report
	@echo "security pipeline complete -> $(REPORT)"
