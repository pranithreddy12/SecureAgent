# ADR-005: In-process asyncio background audits + polling

- **Date:** 2026-10-02
- **Status:** Accepted

## Context
Audits are long-running and must not block request handling. Progress must reach the
UI. The brief asks for the simplest reliable option and to justify Redis/Celery
before adding them.

## Decision
- `POST /audits/{id}/start` launches an `asyncio` task in the API process via an
  `AuditRunner`, bounded by a semaphore (`MAX_CONCURRENT_SCANS`).
- Each stage's output and progress are committed to PostgreSQL immediately.
- Frontend polls `/status` and `/logs` every 2 s.
- Stop: cancellation flag checked between steps + `task.cancel()` + subprocess kill.
- On startup, audits stuck in `running` are marked `failed` ("interrupted by
  restart") and are resumable.
- Single backend replica.

## Alternatives
- Celery + Redis — durable queues and horizontal scaling; two more services. Revisit
  if multi-replica or scheduled audits are needed.
- SSE/WebSockets — nicer UX; polling is simpler and sufficient at 2 s.

## Consequences
- Running audits are lost on process restart (but resumable from the last stage).
- Not horizontally scalable without moving to a real queue.
