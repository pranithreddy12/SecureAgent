# ADR-016: Source-only agent pipeline (phases 4-12 for source files)

- **Date:** 2026-10-11
- **Status:** Accepted (owner request: "build phase 4-12 for source files only")
- **Relates to:** ADR-001 (LangGraph), ADR-003 (safe validation), ADR-005 (background jobs),
  ADR-011 (source audits), ADR-014 (delivered scope), ADR-015 (static recon/validation)

## Context

Phases 4-12 of the brief describe a *live-target* platform. The owner asked for them to be built
for **source files only**. Several phases have a faithful source-only form; two (ZAP, Nuclei) do not.

## Decision

| Phase | Brief | Source-only form (delivered) |
|---|---|---|
| 4 | Target management | **Source projects**: register a directory under `SOURCE_ROOTS`, per-user limit (`MAX_TARGETS_PER_USER`), one project per path, owner-scoped CRUD |
| 5 | Authorization and restrictions | Explicit authorization record (append-only trail, revocable, latest wins); audits require a *current* authorization; path **re-confined at launch and again by the pipeline's authorization gate**; per-user concurrency limit (`MAX_CONCURRENT_SCANS`); revocation between queue and run blocks the run |
| 6 | Agent framework + LangGraph workflow | `app/pipeline/` -- a LangGraph `StateGraph` of seven agents; artifacts persisted in the DB so any stage is idempotent and a failed audit can **resume from the failed stage** |
| 7 | Reconnaissance Agent | Source reconnaissance -> `reconnaissance_results` (technologies, endpoints, inputs, outbound hosts, env vars, routes) |
| 8 | Vulnerability Scanner Agent | The static engine (all detectors) persisting raw findings |
| 9 | OWASP ZAP | **Not applicable** -- a dynamic scanner has no meaning for source files |
| 10 | Nuclei | **Not applicable** -- template-based probing of live hosts |
| 11 | Safe Validation Agent | **Fix verification** (ADR-013): a deterministic patch is applied to a private copy; it must parse and a re-scan must show the finding gone with nothing new. Stored in `validation_result.fix_verification`. It does *not* prove exploitability |
| 12 | Validator Agent | Rule-based reclassification of test/example/dev-only findings (ADR-015); never promotes, never deletes |
| 13 | Report | Report agent builds the HTML report from persisted artifacts (matrix, chains, timeline of agents) |

Pipeline order: `authorization -> reconnaissance -> scanner -> safe_validation -> validator ->
correlation (attack chains) -> report`. A failing stage routes straight to the end with a generic,
path-free error; the stage's `error` is recorded in `stage_state`.

LangGraph specifics: a conditional entry edge routes to the first stage without `completed_at`
(this is what makes resume work); each node records its agent name in `audit_logs`; tracing is
explicitly disabled by default (`LANGCHAIN_TRACING_V2=false`, `LANGSMITH_TRACING=false`) so audit
data cannot reach a third party through a stray developer environment variable.

## Update (2026-10-12)

Two optional AI stages (`ai_validator`, `ai_narrative`) were added in ADR-018. The stages named above stay
deterministic; the AI stages are opt-in, advisory and degrade without failing the audit.

## Not delivered (explicit)

- **Live targets, live reconnaissance, ZAP, Nuclei, exploit-style validation** -- unchanged from
  ADR-014/ADR-015. Nothing in this pipeline opens a socket.
- **LLM reasoning** -- the agents are deterministic; there is no model call.
- **Crash resume of a running audit** -- an audit interrupted by a process restart is marked failed
  (startup sweep); the user can then resume it from the failed stage.

## Alternatives

- **Hand-rolled stage loop** -- simpler, but ADR-001 chose LangGraph and the conditional-entry resume
  maps onto it directly. Cost: ~25 new pinned dependencies (langchain-core, langsmith, ...), none
  with known advisories at the time of locking (checked against OSV).
- **Placeholder `targets` rows for sources** -- rejected in ADR-011.

## Consequences

- `security_audits.source_project_id` links audits to projects (`ON DELETE SET NULL`).
- `resume=true` reuses earlier artifacts and does **not** re-read the source for completed stages;
  use the default clean retry after editing the code.
- The traceability rows for phases 4-12 are *Implemented (source-only)*; their live-target
  counterparts stay Deferred.
