# ADR-043: Four new feature categories (IaC scanning, SBOM, GitHub Action, VS Code extension)

- **Date:** 2026-10-18
- **Status:** Accepted (owner: "i think we need to add more features to the project this is not
  an impressive project to my faculty" -- a features-graded course/capstone context, confirmed
  by question)

## Decision

Add four feature categories that broaden *what SecureAgent is*, rather than deepening SAST
detection again. Each reuses an existing module rather than starting a parallel pipeline.

1. **Infrastructure-as-code scanning** (`app/analysis/misconfig.py`): Kubernetes manifests
   (`privileged`, `runAsUser: 0`, `allowPrivilegeEscalation`, `hostNetwork`/`hostPID`/`hostIPC`)
   and Terraform (`.tf`: public S3 ACLs, security-group ingress open to `0.0.0.0/0`, literal
   credentials in a provider/resource block). `_infra_findings` already existed for
   Dockerfile/compose/CSP; this extends the same function and `CATEGORY` table rather than a
   new analyser. Two existing categories are reused (`privileged_container`,
   `container_runs_as_root`); four are new, one of them new-but-reused
   (`k8s_host_namespace`, `tf_public_bucket`, `tf_open_ingress`, `tf_hardcoded_credential`).
   Fixture: `benchmark/corpus/iac_misconfig.tf`, `iac_misconfig_k8s.yaml` (100% on every new
   category; benchmark total 98%/98%, unchanged on the pre-existing cases).
2. **SBOM** (`app/analysis/sbom.py`, `scan --sbom FILE`): CycloneDX 1.5 JSON built from the
   dependency inventory `dependencies.py` already parses and the OSV lookup `osv.py` already
   runs -- no new scanning, a pure formatter over `ScanResult` (the same split `sarif.py` and
   `reporting.py` use). One component per dependency with a `purl`; a `vulnerabilities` entry
   per OSV advisory found, with its CVSS rating.
3. **GitHub Action** (root `action.yml`, composite): installs `secureagent` from
   `${{ github.action_path }}/backend` (no PyPI publish needed), scans with `--format sarif
   --sbom`, uploads SARIF to the Security tab (`github/codeql-action/upload-sarif`), uploads
   both as artifacts, posts/updates one PR comment with the finding counts by severity (parsed
   from the SARIF, not a second scan), and applies `--fail-on` last so the gate failing still
   lets the upload/comment steps run. The repo's own `self-scan` CI job now uses it
   (`uses: ./`) instead of three manual steps -- dogfooded, not just written.
4. **VS Code extension** (`vscode-extension/`): plain JS, no build step (`ADR-009`'s
   dependency-light philosophy), runs the CLI with `--format sarif --exit-zero` on activation
   and ~400ms after each save, and renders the result as `vscode.Diagnostic`s via
   `DiagnosticCollection`. The SARIF-to-per-file grouping (`groupSarifByFile`) is written as a
   pure function with `vscode` required behind a `try`/`catch` specifically so it stays
   testable from plain Node (`extension.test.js`, no `vscode` test harness).

## Consequence

Backend: 2 new misconfig categories tested (one reused, three new), 1 new CLI flag, 1 new
module (`sbom.py`), 9 new tests (`test_infra_checks.py` +2, `test_sbom.py` +2, `test_cli_standalone.py`
+1), author-written benchmark 98%/98% (was 97%/97%; the two new fixture files add true
positives, no new false positives). CI: the self-scan job now exercises `action.yml` on every
push/PR, so a broken Action fails CI the same day, not when a consuming repo tries it.

## Not claimed

The VS Code extension has no marketplace listing (`F5`/Extension Development Host only). The
GitHub Action has not been exercised from a *different* repository yet -- only dogfooded on
this one. IaC checks are regex-based on manifest text, not a real HCL/YAML parser, so they can
miss or misfire on unusual formatting the same way the existing Dockerfile/compose checks can.
