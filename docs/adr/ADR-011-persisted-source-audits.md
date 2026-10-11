# ADR-011: Persisted source audits (no live target required)

- **Date:** 2026-10-11
- **Status:** Accepted
- **Extends:** ADR-005 (background jobs), ADR-008 (grey-box), ADR-010 (business-logic detectors)

## Context

The static-analysis engine only ran from the CLI, so nothing was persisted: no audit history,
progress, logs or downloadable report (acceptance criteria 8, 9, 21, 22, 23). The live-target
pipeline is still blocked on target management. Source audits do not touch the network, so they
need none of the live-target network checks and can be delivered now.

## Decision

A **source audit** is a `security_audits` row with `audit_type = 'source'`, no target, and the
analysed directory in `source_path`.

- **Confinement.** The server only analyses directories under `SOURCE_ROOTS` (comma-separated
  absolute paths, resolved including symlinks and `..`). Unset = the feature is disabled (503).
  Docker Compose mounts `./workspace` read-only at `/workspace` and sets `SOURCE_ROOTS=/workspace`.
- **Authorization gate.** `authorization_confirmed: true` is required in the request; the
  statement and timestamp are stored on the audit and printed in the report.
- **Runner.** An asyncio task per audit (ADR-005). The CPU-bound scan runs in a worker thread.
  Stages (`scan`, `persist`, `report`) update `stage_state`, `progress` and `audit_logs`; any failure
  marks the audit `failed` with a generic message (no filesystem paths) and an error log row.
- **Persistence.** Findings go to `vulnerabilities` (fingerprint de-duplicated per audit), the
  rendered HTML to `security_reports`.
- **Ownership.** Every endpoint filters on the authenticated user; another user's audit is a 404.
- **Honesty unchanged.** Persisted findings keep the analyser's statuses (never `confirmed` from
  static analysis), and the report keeps its static-only limitations.

## Alternatives

- **Upload a zip** — avoids server paths but needs hardened extraction (zip-slip, bombs); deferred.
- **Placeholder `targets` rows** — would route source audits through target management we cannot
  build, and fake a URL. Rejected in favour of a nullable `target_id` + `audit_type`.
- **Celery/Redis** — rejected in ADR-005.

## Consequences

- Schema change (nullable `target_id`, `audit_type`, source and authorization columns) with an
  Alembic migration and a CHECK keeping live audits tied to a target.
- Audits that are `running` when the process dies stay `running` (no resume yet); a restart
  recovery sweep is future work.
- Path confinement is only as strong as the operator's `SOURCE_ROOTS` choice.
