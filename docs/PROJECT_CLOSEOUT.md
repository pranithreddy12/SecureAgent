# SecureAgent – Project Close-out

Date: 2026-10-11 · Repository: `main` (CI green on all four jobs: backend, frontend, self-scan, end-to-end)

Evidence at close-out: **463 backend tests pass (2 skipped: PDF, which CI runs, and a Windows-only symlink case), 93% line coverage ·
33 frontend unit tests · 7 Playwright browser tests · 16 ADRs · detector benchmark 97% precision / 95%
recall on the bundled corpus · self-scan clean (0 new findings; 1 accepted advisory)**.

**Decision (2026-10-11): the owner chose Option 1 (§6) -- the project is closed as a grey-box static
security auditor; see ADR-014.** The live pipeline is deferred, not in progress.

This is a blunt statement of what exists, what does not, and why. Nothing here claims more than the
code does. It supersedes the 2026-10-09 close-out audit (kept in git history).

## 1. Verdict

| | |
|---|---|
| **What exists and works** | A tested, installable **grey-box static application-security auditor**: scanner + CLI (`secureagent`), MCP server, web app with persisted source audits (history, live progress, findings, attack chains, logs, HTML/PDF reports), CI baseline/gating, SARIF, verified fix patches, accuracy benchmark. |
| **What does not exist** | The **live-target** pipeline: URL targets and network-safety validation, live reconnaissance, OWASP ZAP and Nuclei (not applicable to source files), exploit-style safe validation, any LLM reasoning. The **source-only** pipeline (projects, authorization, seven LangGraph agents, resume) exists (ADR-016). |
| **Why** | All of it depends on target management (network-safety validation of target URLs). Generating those two files was halted by an automated safety classifier and I may not regenerate that content; the requirement is legitimate and unchanged. The hand-off specification is `docs/target-management-implementation.md`. |
| **Can it be presented as complete?** | **As "a grey-box static security auditor with business-logic checks", yes** -- it is real, demonstrable, honest and CI-verified. **As the full live multi-agent platform in the original brief, no.** Choose one framing and state it plainly (§6). |

## 2. Acceptance criteria (original brief §47) -- all 28

Legend: ✅ done · ✅s done for **source audits** only (live-target form blocked) · ◐ partial · ⛔ not built

| # | Criterion | Status | Evidence / gap |
|---|---|---|---|
| 1 | Start the project | ✅ | `docker compose up --build`; CLI via `pip install ./backend` |
| 2 | Open the dashboard | ✅ | `/dashboard`: live health and real audit counts, nothing simulated |
| 3 | Register | ✅ | `/api/auth/register`, `/register`; Playwright-tested |
| 4 | Login | ✅ | Argon2id, JWT httpOnly cookie, throttling (429 after 5 failures) |
| 5 | Create an authorized target | ✅s | Source projects (ADR-016): registered, owner-scoped, limited per user. Live URL targets not built |
| 6 | Confirm authorization | ✅s | Per-project append-only authorization trail, revocable, required before any audit; checked again by the pipeline gate |
| 7 | Validate target scope | ✅s | Source paths confined to `SOURCE_ROOTS` (symlinks/`..` resolved) at registration, launch and by the gate. Network-target scope validation not built |
| 8 | Start an audit | ✅s | `POST /api/audits/source`, `/audits` UI (ADR-011) |
| 9 | See audit progress | ✅s | Persisted stages, polling UI, activity log |
| 10 | Run reconnaissance | ✅s | Reconnaissance agent in the pipeline builds the application model from source (ADR-015/016). **Live** reconnaissance not built |
| 11 | Discover endpoints | ◐ | Static route discovery in 5 frameworks + authorization matrix; no live crawling |
| 12 | Run vulnerability scanning | ◐ | Static engine ✅; ZAP/Nuclei ⛔ |
| 13 | Produce potential findings | ✅ | All detectors; honest statuses (never `confirmed` from static analysis) |
| 14 | Safely validate findings | ◐ | Source form: verified fix patches and rule-based validation run as pipeline agents (ADR-013/015/016). They prove a fix removes a finding, **not** that a flaw is exploitable; live safe validation not built |
| 15 | Reduce false positives | ◐ | Heuristic status/confidence, de-duplication, suppression, baseline, sanitizer modelling, rule-based validation (ADR-015), measured benchmark; no dynamic Validator |
| 16 | Assign severity | ✅ | Per detector; chains never exceed their worst member |
| 17 | Map OWASP/CWE | ✅ | Every finding carries OWASP category + CWE |
| 18 | CVE/CVSS where appropriate | ✅ | CVE only from real OSV advisories; CVSS computed from the advisory's own v3 vector (real `braces` check: 7.5, matching the published score); no vector -> "not determined" |
| 19 | Generate remediation | ✅ | Per type, grouped in the report, plus verified patches for 7 types |
| 20 | Professional report | ✅ | 19 sections, risk rating, fix-first, attack chains, authorization matrix, DEMO labelling |
| 21 | Download PDF/HTML | ✅ | `GET /api/audits/{id}/report?format=html\|pdf`, UI links, CLI |
| 22 | View historical audits | ✅ | `GET /api/audits`, history table |
| 23 | View audit logs | ✅ | `GET /api/audits/{id}/logs`, activity log on the audit page |
| 24 | Run DEMO MODE without external credentials | ◐ | `secureagent demo` offline ✅; no fixture-driven demo of the agent pipeline |
| 25 | Run automated tests | ✅ | pytest + Vitest + Playwright, all in CI |
| 26 | Run through Docker Compose | ◐ | Stack runs and is e2e-tested; ZAP/juice-shop defined but unused, Nuclei not in the image |
| 27 | Recover from a failed audit stage | ✅s | Per-stage errors recorded; interrupted audits marked failed; retry (clean) **or resume from the failed stage** reusing earlier artifacts |
| 28 | Preserve context across sessions | ✅ | Memory, changelog, 16 ADRs, traceability R1-R64, this close-out |

**Tally: ✅ 15 · ✅s 7 · ◐ 6 · ⛔ 0** (28). At the 2026-10-09 close-out it was ✅ 11 · ◐ 8 · ⛔ 9.

## 3. What was delivered since the 2026-10-09 close-out

| Area | Delivered |
|---|---|
| Detection depth | Business-logic detectors (client-trusted values, mass assignment, privilege fields), JSON intent spec, authorization matrix + inconsistent-authorization outliers, workflow-order heuristic, attack chains (ADR-010, ADR-012) |
| Trust | Accuracy benchmark with a deliberately imperfect corpus (`docs/benchmark.md`); self-scan caught and fixed 3 false positives in its own code, the benchmark found 2 more gaps |
| Product | Persisted source audits end to end: API, runner, migration, UI, report download (ADR-011); login throttling; interrupted-audit sweep; admin bootstrap |
| Developer workflow | MCP server (`scan_snippet`, `scan_path`, `suggest_fixes`, `authorization_matrix`); verified fix patches (ADR-013) |
| Quality | 346 backend / 24 unit / 6 browser tests; four-job CI |

## 4. Bugs the project's own tooling found in its own code

| Finding | Fix |
|---|---|
| Installed CLI crashed without SQLAlchemy (enums in the ORM package) | Enums moved to a stdlib module; test that poisons web-stack imports (ADR-009) |
| `poetry.lock`/`Pipfile.lock` never scanned (`.lock` treated as binary) | Fixed + ingestion regression test |
| Python open redirect never reported; `eval("literal")` flagged | Found by the first benchmark run; fixed |
| Parameterised SQLAlchemy `select()` reported as SQL injection | Fixed (nested `text()` still flagged) |
| `user: CurrentUser` FastAPI alias not recognised as an auth guard | Fixed |
| Env-var *names* (`PASSWORD_ENV = "APP_PASSWORD"`) reported as secrets | Fixed |
| Chain severities all inflated to CRITICAL (first draft) | Chains never exceed their worst member (ADR-012) |
| Vitest 3 pulled critical advisories (tinypool RCE gadget) | Vitest 5 + `@types/node@^22` |

## 5. Remaining work

### A. Owner action (with Option 1 chosen, only items 2-3 remain for delivery)
1. *(Only if Option 2 is ever resumed)* **Supply `backend/app/security/target_validation.py` and `backend/app/services/target_service.py`**
   per `docs/target-management-implementation.md`. This single step unblocks criteria 5, 7, 10, 12 (live),
   14 and the live form of 8/9.
2. ~~Choose a `LICENSE`~~ -- **MIT chosen by the owner (2026-10-11)**; `LICENSE` added.
3. **Provide the PPT** so the PENDING sections of `SPECIFICATION.md` can be filled and conflicts surfaced.
4. **Decide the closing framing** (§6).
5. **Accepted advisory:** `braces 3.0.3` (GHSA-vfj7-8cjw-p6xm), dev-only transitive dependency, no patched
   version exists; recorded in `.secureagent-baseline.json`. Revisit when a fix ships.

### B. Live-target pipeline (deferred; assistant can build once A1 exists)
1. Authorization service + `/api/targets`, `/authorize`, `/validate` + the security-restriction tests.
2. Live-audit entity/runner reusing the ADR-011 runner and stage persistence.
3. Recon, ZAP and Nuclei integration (scope-checked, no `shell=True`); Nuclei in the image.
4. Safe Validation, Validator and Report agents; LangGraph workflow wiring the static engine as the
   Code Intelligence stage.
5. Targets/findings/reports pages; optional LLM reasoning with deterministic fallback.

### C. Independent improvements (any time)
- Detector accuracy on an **independent** labelled corpus (the bundled one is author-written).
- JS/TS AST-based analysis (replace regex heuristics); per-kind sanitizer tracking; CVSS v4/v2 scoring.
- Zip upload for source audits; stage-level audit resume; multi-worker-safe throttling and sweep.
- Authorization matrix grouping beyond the first path segment; Application Model persistence.
- Browsers other than Chromium in e2e; frontend coverage reporting.
- *(Done since the close-out: CVSS v3 scoring, sanitizer modelling, matrix refinement for public listings,
  audit retry, accessible form fields.)*

## 6. Two honest ways to close the project

**Option 1 -- close as a grey-box static security auditor (achievable now). ✅ CHOSEN 2026-10-11 (ADR-014).** Everything claimed is
true and reproducible: `secureagent demo`, `secureagent scan`, `secureagent fix`, the web app's source
audits, the MCP server, the benchmark. Needs only A2-A5. The README and this document already frame it
this way. **Recommended.**

**Option 2 -- complete the original live multi-agent platform (deferred; not chosen).** Requires A1, then roughly B1-B5.
The only route to criteria 5, 7, 10, 14 and the live forms of 8-9.

## 7. How to verify this close-out yourself

```bash
make testdb && cd backend && python -m pytest -q            # 346 passed, 1 skipped
python -m coverage run --source=app -m pytest -q && python -m coverage report   # ~93%
secureagent scan . --baseline .secureagent-baseline.json --fail-on high         # 0 new (online OSV)
secureagent benchmark backend/benchmark/corpus              # 94% / 94%, known misses listed
secureagent demo                                            # labelled DEMO report (34 findings)
cd frontend && npm test && npm run typecheck && npm run build
docker compose up --build -d backend frontend && npm run e2e   # needs ./workspace/shop (frontend/e2e/README.md)
git ls-files | grep -iE "claude|agents.md"                  # nothing tracked
```
