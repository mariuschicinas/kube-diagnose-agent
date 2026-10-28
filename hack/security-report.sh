#!/usr/bin/env bash
# Generates security-report.md: an aggregated supply-chain and posture report.
#
# Run:  make security     (vendor + sbom + report)
#   or: ./hack/security-report.sh
#
# Requires the scanners: make tools
set -uo pipefail

REPORT="security-report.md"
GOBIN="$(go env GOPATH)/bin"
export PATH="$PATH:$GOBIN"

have() { command -v "$1" >/dev/null 2>&1; }

echo "==> generating $REPORT"

{
  echo "# Security Report — kube-diagnose-agent"
  echo
  echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "Commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'not a git repo')"
  echo "Go: $(go version | awk '{print $3}')"
  echo
  echo "This report covers (1) supply chain: what third-party code this binary"
  echo "pulls in and whether any of it is known-vulnerable, and (2) runtime"
  echo "posture: what the agent is architecturally able to do. See SECURITY.md"
  echo "for the threat model."
  echo
  echo "---"
  echo
} > "$REPORT"

## 1. Dependency inventory
{
  echo "## 1. Dependency inventory"
  echo
  # -mod=mod is required: with a vendor/ dir present, 'go list -m all' fails.
  MAIN=$(go list -mod=mod -m 2>/dev/null | head -1)
  # {{.Version}} is empty for the main module, so filtering on a version field
  # also drops it; filter by path too for safety.
  DIRECT=$(go list -mod=mod -m -f '{{if and (not .Indirect) .Version}}{{.Path}} {{.Version}}{{end}}' all 2>/dev/null | grep -v "^${MAIN} " | grep -cv '^$' || echo 0)
  TOTAL=$(go list -mod=mod -m all 2>/dev/null | grep -cv '^$' || echo 0)
  echo "- Direct modules: **${DIRECT}**"
  echo "- Total modules in graph (incl. transitive): **${TOTAL}**"
  echo
  echo "The graph is large because \`client-go\` is large. That is inherent to any"
  echo "Kubernetes client and is not by itself a red flag; what matters is whether"
  echo "any of it is reachable AND vulnerable (see section 2)."
  echo
  echo "<details><summary>Direct dependencies</summary>"
  echo
  echo '```'
  go list -mod=mod -m -f '{{if and (not .Indirect) .Version}}{{.Path}} {{.Version}}{{end}}' all 2>/dev/null | grep -v '^$' || echo "(go list failed — run 'go mod tidy' first)"
  echo '```'
  echo
  echo "</details>"
  echo
} >> "$REPORT"

## 2. govulncheck — reachability-aware
{
  echo "## 2. Known vulnerabilities (govulncheck — reachability analysis)"
  echo
  echo "govulncheck reports a vulnerability only if the vulnerable **function** is"
  echo "actually callable from this codebase. This is the signal that matters."
  echo
  echo '```'
} >> "$REPORT"

if have govulncheck; then
  GOVULN_OUT=$(govulncheck ./... 2>&1)
  VULN_RC=$?
  echo "$GOVULN_OUT" >> "$REPORT"
  # Distinguish "found vulnerabilities" from "scanner failed to run": a real
  # finding always names at least one advisory ID.
  if [ "$VULN_RC" -ne 0 ] && ! echo "$GOVULN_OUT" | grep -q 'Vulnerability #'; then
    VULN_RC=2 # scanner error, not a finding
  fi
else
  echo "govulncheck not installed — run: make tools" >> "$REPORT"
  VULN_RC=127
fi

{
  echo '```'
  echo
  if [ "$VULN_RC" -eq 0 ]; then
    echo "**Result: no reachable vulnerabilities.**"
  elif [ "$VULN_RC" -eq 127 ]; then
    echo "**Result: not run (scanner missing — \`make tools\`).**"
  elif [ "$VULN_RC" -eq 2 ]; then
    echo "**Result: scanner error (not a finding).** govulncheck failed to run;"
    echo "the output above is an error, not a vulnerability. Investigate before"
    echo "treating this section as a pass."
  else
    echo "**Result: reachable vulnerabilities found — actionable.** Each trace"
    echo "above shows the call path from this codebase into the vulnerable"
    echo "function. Fix by upgrading the named module, e.g.:"
    echo '```'
    echo "go get <module>@<fixed-version> && go mod tidy && govulncheck ./..."
    echo '```'
  fi
  echo
} >> "$REPORT"

## 3. Manifest-level scanning: deliberately not used
{
  echo "## 3. Manifest-level scanning: deliberately not used"
  echo
  echo "A manifest-level scanner (e.g. osv-scanner) was evaluated and removed."
  echo "On this repository it reported roughly 44 advisories, of which **zero**"
  echo "were actionable:"
  echo
  echo "- It reads the Go version *declared* in \`go.mod\`, not the toolchain the"
  echo "  binary is actually built with, so it flags stdlib CVEs that are already"
  echo "  patched in the compiler in use."
  echo "- It rescans the vendored tree, duplicating every finding."
  echo "- It cannot tell whether vulnerable code is reachable, so an advisory deep"
  echo "  in the client-go dependency graph looks identical to one on a hot path."
  echo
  echo "A gate that cries wolf 44 times trains its readers to ignore it, which is"
  echo "worse than having no gate. Reachability analysis (section 2) is the"
  echo "authoritative signal here: before the \`golang.org/x/net\` pin it reported"
  echo "exactly 2 vulnerabilities, both genuinely callable from this codebase, and"
  echo "both were fixed. That is a gate worth enforcing."
  echo
  echo "If a client's policy mandates manifest-level scanning, run it separately"
  echo "and triage stdlib findings against the actual build toolchain."
  echo
} >> "$REPORT"

{
  echo "## 4. Supply-chain integrity"
  echo
  echo "Go verifies every module against \`go.sum\` and, by default, against the"
  echo "public checksum transparency log (sum.golang.org) — a tamper-evident log,"
  echo "analogous to Certificate Transparency. A modified module fails the build."
  echo "Go also runs no install-time scripts (no npm-style \`postinstall\`), so"
  echo "fetching a dependency does not execute its code."
  echo
  echo '```'
  echo "\$ go mod verify"
} >> "$REPORT"

go mod verify >> "$REPORT" 2>&1 || echo "(verify failed — investigate)" >> "$REPORT"

{
  echo '```'
  echo
  if [ -f sbom.json ]; then
    COMPONENTS=$(grep -o '"bom-ref"' sbom.json 2>/dev/null | wc -l | tr -d ' ')
    echo "SBOM: \`sbom.json\` (CycloneDX, ${COMPONENTS} components) — regenerate with \`make sbom\`."
  else
    echo "SBOM: not generated. Run \`make sbom\`."
  fi
  echo
} >> "$REPORT"

## 5. Runtime posture — the part that actually distinguishes this tool
{
  echo "## 5. Runtime security posture"
  echo
  echo "Supply-chain hygiene above is table stakes. This section is the posture"
  echo "that matters for running an LLM-driven agent next to regulated data."
  echo
  echo "| Control | Mechanism | Enforced by |"
  echo "|---|---|---|"
  echo "| No write access to the cluster | ServiceAccount has no write verbs | **RBAC** (\`deploy/rbac.yaml\`) |"
  echo "| No cross-namespace reads | Tool calls outside the target namespace are refused before any API call | **Code** (\`internal/tools\`) |"
  echo "| No arbitrary command execution | 3 typed, scoped read tools; no exec/shell tool exists | **Code** (tool surface) |"
  echo "| Secrets are masked before egress (best-effort) | Every section is scrubbed for known credential shapes before it leaves the process; unrecognisable high-entropy secrets can still pass | **Code** (\`internal/redact\`) |"
  echo "| Logs cannot issue instructions | Untrusted fence + neutralized control syntax + system-prompt trust boundary | **Prompt + code** (probabilistic) |"
  echo "| Bounded investigation | Hard cap on tool-call rounds | **Code** (\`--max-iterations\`) |"
  echo "| Auditability | Every tool call traced; refusals raised as SECURITY warnings | **Code** (\`internal/diagnose\`) |"
  echo
  echo "Verify egress yourself at any time:"
  echo
  echo '```'
  echo "./bin/agent diagnose -n <ns> <pod> --show-bundle   # prints exactly what was sent"
  echo '```'
  echo
  echo "**The honest limits** (detail in SECURITY.md): the prompt-level injection"
  echo "defences are probabilistic, not guarantees. Only the RBAC boundary and the"
  echo "namespace allowlist are hard walls. The design assumes the model *may* be"
  echo "fooled and ensures a fooled model still cannot act."
  echo
} >> "$REPORT"

echo "==> wrote $REPORT"
echo
echo "Summary:"
if [ "$VULN_RC" -eq 0 ]; then
  echo "  govulncheck: PASS (no reachable vulnerabilities)"
elif [ "$VULN_RC" -eq 127 ]; then
  echo "  govulncheck: SKIPPED (not installed — run 'make tools')"
elif [ "$VULN_RC" -eq 2 ]; then
  echo "  govulncheck: ERROR (scanner failed to run — see $REPORT section 2)"
else
  echo "  govulncheck: REACHABLE VULNERABILITIES — see $REPORT section 2"
fi
