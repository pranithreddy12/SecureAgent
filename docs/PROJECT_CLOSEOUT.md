# SecureAgent – Project Close-out Audit

Date: 2026-10-09 · Repository state: `main` · First CI run found and led to fixing two failures · Backend tests: **253 collected, 252 pass, 1 skipped
(PDF; passes in Docker), 0 fail** · Coverage: **93%** · Lint/format/types: clean.

This is an audit of the project against the original brief — what is finished, what is not, why,
and exactly what is left. It is deliberately blunt: nothing here claims more than the code does.

## 1. Verdict

| | |
|---|---|
| **What exists and works** | A tested, installable **static application-security scanner** (`secureagent`) covering OWASP Top 10 A01–A03 and A05–A10 in Python and JavaScript across five web frameworks, with HTML/PDF/JSON/SARIF output, CI baseline/gating, suppression controls and a bundled demo. Plus a **web-app skeleton**: authentication, PostgreSQL schema + migrations, Docker Compose, a frontend login/dashboard shell. |
| **What does not exist** | The **live multi-agent audit pipeline**: target management, the authorization gate for audits, reconnaissance, OWASP ZAP and Nuclei integration, safe validation, validator, LangGraph workflow, audit runner/progress, audit logs, audit persistence, and the frontend pages for them. |
| **Why** | Target management — specifically the network-safety validator and the target service — is the prerequisite for everything above. Generation of those two files was halted twice by an automated safety classifier and the assistant may not regenerate that content. The requirement itself is legitimate and unchanged; the owner must supply the two files (specification: `docs/target-management-implementation.md`). |
| **Can the project be presented as complete?** | **As "a static-analysis-centred security auditor", yes** — it is real, demonstrable and honest. **As the full multi-agent live-audit platform in the brief, no** — acceptance criteria 5–10, 14, 22, 23 and 27 are unmet. Choose one framing and state it plainly (see §6). |

## 2. Acceptance criteria (brief §47) — status of all 28

Legend: ✅ done · ◐ partial · ⛔ not built

| # | Criterion | Status | Evidence / gap |
|---|---|---|---|
| 1 | Start the project | ✅ | `docker compose up --build` (stack builds, backend healthy); CLI via `pip install -e backend` |
| 2 | Open the dashboard | ✅ | `/dashboard` with live backend status (no simulated metrics) |
| 3 | Register | ✅ | `POST /api/auth/register`, `/register` page |
| 4 | Login | ✅ | Argon2id, JWT httpOnly cookie, `/login` page, sign-out |
| 5 | Create an authorized target | ⛔ | Blocked (target management) |
| 6 | Confirm authorization | ⛔ | Blocked; schema + `authorization_records` table exist |
| 7 | Validate target scope | ⛔ | Blocked (`target_validation.py`) |
| 8 | Start an audit | ◐ | `secureagent scan` runs a source audit; no audit entity/API/UI |
| 9 | See audit progress | ⛔ | No runner/progress |
| 10 | Run reconnaissance | ⛔ | Not built (live recon). Static route extraction exists |
| 11 | Discover endpoints | ◐ | Static discovery of routes from source in 5 frameworks; no live crawling |
| 12 | Run vulnerability scanning | ◐ | Static engine ✅; ZAP/Nuclei ⛔ |
| 13 | Produce potential findings | ✅ | All detectors; honest statuses |
| 14 | Safely validate findings | ⛔ | Safe Validation agent not built (ADR-003 design only) |
| 15 | Reduce false positives | ◐ | Heuristic status/confidence, de-dup, suppression, baseline; no Validator agent |
| 16 | Assign severity | ✅ | Per detector; never inflated |
| 17 | Map OWASP/CWE | ✅ | Every finding carries OWASP category + CWE |
| 18 | CVE/CVSS where appropriate | ◐ | CVE from real OSV advisories ✅; **CVSS is never populated** for OSV findings (reported "CVSS not determined") |
| 19 | Generate remediation | ✅ | Per finding type, grouped in the report |
| 20 | Professional report | ✅ | 19 sections, risk rating, Fix-first, ToC, DEMO labelling |
| 21 | Download PDF/HTML | ◐ | Via CLI (`--report`, `--pdf`); no download endpoint/UI |
| 22 | View historical audits | ⛔ | CLI scans are not persisted |
| 23 | View audit logs | ⛔ | `audit_logs` table only |
| 24 | Run DEMO MODE without external credentials | ◐ | `secureagent demo` ✅ (offline); fixture demo of the agent pipeline ⛔ |
| 25 | Run automated tests | ✅ | `pytest` (253) |
| 26 | Run through Docker Compose | ◐ | Stack runs; ZAP/juice-shop defined but unused; Nuclei binary not in image |
| 27 | Recover from a failed audit stage | ⛔ | Designed (`stage_state`); no runner |
| 28 | Preserve context across sessions | ✅ | Memory, changelog, 9 ADRs, traceability, close-out |

**Tally: ✅ 11 · ◐ 8 · ⛔ 9.**

## 3. Phases (brief §36)

0–3 done · **4–5 blocked** · 6–12 not started (depend on 4–5) · 13 rendering done, Report *agent*
pending · 14 shell done · 15 not started · 16 static demo done · 17 partial · 18 partial · 19 not
done · 20 done for existing code. Beyond the brief's list (scope change 2026-10-03b, ADR-008): the
grey-box static engine, CLI, CI gating, SARIF.

## 4. What this audit found and fixed (2026-10-09)

The audit method was to *use* the product on itself and to test the *installed* artifact — which
found defects 200+ unit tests had not:

| Finding | Severity | Fix |
|---|---|---|
| **Installed `secureagent scan` crashed on a clean machine** — the scanner imported the ORM package (SQLAlchemy) via a shared enum module; the dev virtualenv masked it | High (the main command was broken for any real user) | Enums moved to `app/core/enums.py`; ADR-009; `test_cli_standalone.py` (runs with web-stack imports poisoned) |
| **`poetry.lock` and `Pipfile.lock` were never scanned** — `.lock` was classed as a binary extension; unit tests bypassed ingestion | High (silent false negatives in SCA) | Removed; end-to-end regression test |
| Handlers sharing a method name across classes (`get`, `post`) were collapsed and some never analysed | Medium | Handler loops walk all function nodes |
| Secret false positives: `{PLACEHOLDER}`, `credentials: "same-origin"`; one key reported twice | Medium (noise erodes trust) | Rules fixed + tests |
| No way to suppress findings except a baseline | Medium (not adoptable on real repos) | `--exclude`, `.secureagentignore`, inline `secureagent: ignore`, always counted |
| Backend dependencies unpinned → SCA saw none; builds not reproducible | Medium (supply chain) | `requirements.lock` (45 pins on python:3.12), Docker installs it; live OSV check: clean |
| CLI crashed on non-ASCII output on Windows consoles (earlier) | Medium | UTF-8 reconfigure |
| Swallowed exception in the CLI (flagged by its own A09 check) | Low | `contextlib.suppress` |
| Documentation drift: stale traceability rows, missing changelog entry, 200-line memory §3 | Medium (breaks "context across sessions") | Corrected; memory restructured |
| Missing required docs (`testing.md`, `deployment.md`), partial README, no repo CI | Medium | Written; CI workflow added |
| `frontend/AGENTS.md`, `frontend/CLAUDE.md` tracked (tool-generated) | Low (owner asked for no Claude traces) | Untracked + git-ignored (first attempt was silently undone by a `git reset`; redone and verified against HEAD) |
| First GitHub CI run: frontend `tsc` failed on a clean checkout; self-scan gate failed on `braces` | Medium (CI red) | `npm run typecheck`; baseline for the unpatched dev-only advisory |

Report polish delivered in the same pass: risk rating, "Fix first" priorities, hotspots, ToC,
consolidated findings, compact CVE/CVSS, denser layout (demo PDF 33 → 25 pages).

## 5. Remaining work

### A. Owner action required (blocks everything else)
1. **Supply `backend/app/security/target_validation.py` and `backend/app/services/target_service.py`**
   per `docs/target-management-implementation.md` (signatures, rules, required tests). Mostly stdlib
   `ipaddress` + CRUD with ownership checks.
2. **Decide the closing framing** (see §6).
3. **Choose a `LICENSE`** (none exists; this is the owner's call).
4. **Provide the PPT** so the PENDING sections of `SPECIFICATION.md` can be filled and any conflicts
   with this implementation surfaced.
5. **CI is green** (second run, commit 64f118b: backend, frontend, self-scan all pass). First run (2026-10-09): backend passed; frontend and self-scan failed on real
   issues (Next route types before `tsc`; the `braces` advisory) — both fixed and re-pushed; check the
   Actions tab for the second run. `braces 3.0.3` has **no patched version** (OSV `last_affected: 3.0.3`),
   is a dev-only transitive dependency, and is accepted in `.secureagent-baseline.json`; revisit when a fix ships.

### B. Assistant can build once A1 exists (in order)
1. Authorization service + `/api/targets`, `/authorize`, `/validate` + tests (the security-restriction tests the brief requires).
2. Audit entity/API (`/api/audits*`), background runner with stage persistence (ADR-005), audit logs with `[AUDIT-id]` structured logging.
3. Reconnaissance tool/agent; ZAP and Nuclei integration (safe, scope-checked, no `shell=True`); Nuclei in the image.
4. Safe Validation agent (ADR-003), Validator agent, Report agent; LangGraph workflow wiring the existing static engine as the Code Intelligence stage.
5. Frontend: targets/audits/findings/reports/activity pages, dashboard data and charts, progress polling.
6. Optional LLM reasoning with deterministic fallback; fixture-driven demo of the pipeline.

### C. Independent of the blocker (can be done any time)
- Frontend tests (component + one Playwright e2e of register→login→dashboard).
- Login rate limiting / lockout; admin bootstrap command; production cookie/CORS checklist.
- Detector accuracy benchmark on public vulnerable corpora (the current tests prove intended behaviour, not a measured detection rate).
- Parse OSV CVSS vectors into scores (so CVSS can be shown when reliably determined).
- JS AST-based analysis (replace regex heuristics); sanitizer modelling in taint.
- Workflow-order and client-trusted-value detectors from ADR-008 (the unbuilt part of the business-logic goal).

## 6. Two honest ways to close the project

**Option 1 — close as a static-analysis-centred auditor (achievable now).** Present SecureAgent as a
grey-box *source-code* security auditor: the working scanner, reports, CI integration, demo and the
web skeleton, with the live-audit pipeline documented as designed future work. Everything claimed is
true and reproducible (`secureagent demo`, `secureagent scan backend --exclude tests/`). Requires only
A2–A5 above. The README and this document already frame it this way.

**Option 2 — complete the original multi-agent platform.** Requires A1, then roughly work items B1–B6.
This is the larger body of work and the only route to criteria 5–10, 14, 22–23, 27.

Recommendation: ship Option 1 now (it is complete and defensible), and treat Option 2 as a clearly
labelled second phase once the two files exist.

## 7. How to verify this audit yourself

```bash
make testdb && cd backend && python -m pytest -q          # 252 passed, 1 skipped
python -m coverage run --source=app -m pytest -q && python -m coverage report   # ~93%
secureagent scan . --no-osv                                # clean (exit 0); suppression counted
secureagent scan backend --exclude tests/                  # live OSV check of the pinned lock
secureagent demo --report demo.html                        # labelled DEMO report
git ls-files | grep -iE "claude|agents.md"                 # nothing tracked
```
