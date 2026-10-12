# ADR-019: Zip upload in the web UI, owner triage, and the MCP `explain_finding` tool

- **Date:** 2026-10-12
- **Status:** Accepted (owner: "proceed")
- **Relates to:** ADR-011 (source audits), ADR-016 (pipeline), ADR-009/MCP, ADR-013/017 suppression and review

## Context

Three usability gaps remained after the pipeline work:
1. Web audits needed a directory mounted under `SOURCE_ROOTS`; trying the app meant copying code into
   `./workspace` on the server.
2. A finding judged "not real" could only be recorded in the CLI (`secureagent suppress`), which writes a file
   into the repository -- impossible for a read-only mounted workspace.
3. An AI assistant using the MCP server could list findings but not get the evidence needed to judge one.

## Decision

### 1. Zip upload (`POST /api/projects/upload?name=...`, body = raw `application/zip`)

The archive is **untrusted input**. It is unpacked, never executed, into
`UPLOAD_DIR/<user_id>/<random>/` and then audited exactly like a mounted directory.

| Threat | Control |
|---|---|
| Oversized upload | body streamed with a hard cap (`MAX_UPLOAD_MB`, 25) -> 413 |
| Zip-slip (`../`, absolute, `C:`, backslashes) | every member name normalised and rejected; resolved target must be inside the workspace |
| Symlinks / device files | any entry whose mode is not regular file or directory -> reject |
| Zip bomb | limits on file count (`MAX_UPLOAD_FILES`) and on **bytes actually written** (`MAX_UPLOAD_UNPACKED_MB`), not on declared sizes |
| Encrypted members | rejected |
| Leftovers on failure | workspace deleted on any error |
| Cross-user access | path contains the owner's id and a random token; the normal `POST /projects` refuses any path under `UPLOAD_DIR`, so another user's upload cannot be registered |
| Retention | the workspace is deleted when the project is deleted; per-user project limit still applies |

A single wrapping folder (`repo-main/`) is flattened. Authorization is still confirmed per project before
any audit. The feature is disabled (503) unless `UPLOAD_DIR` is set; Compose sets it to a named volume.
No new dependency: the body is read as a raw stream, so `python-multipart` is not needed.

### 2. Owner triage

`PATCH /api/audits/{id}/findings/{finding_id}/triage` with `{false_positive, reason}` (reason >= 10
characters when marking). The finding becomes `false_positive` with the owner and reason recorded; the
original status and reason are kept in `validation_result.triage` and restored on undo. Completed audits
only; the lookup is scoped by audit **and** owner. The stored HTML report is a snapshot and is not
regenerated.

### 3. MCP `explain_finding`

`explain_finding(path, id)` returns, for one finding: status and reason, evidence, the numbered taint path,
remediation, and the code the LLM layer would see (enclosing function plus up to three resolved helpers,
secrets redacted). Scan results now carry a stable 8-character `id`. The assistant is the judge; the server
makes no model call and stays read-only and path-confined.

## Not claimed / limits

- Upload does not make the audit "safer to run on strangers' code" than before: the code was never run.
  It does add a place where the server stores user data; operators should size the volume and quota.
- Triage is per audit; it does not (yet) write a suppression that applies to future audits. Use the CLI
  suppression file for that.
- Per-user disk quota is the project limit times the unpacked cap, not a separate accounting.
- Archives other than zip (tar.gz, rar) are not accepted.

## Alternatives

- **multipart/form-data** -- needs `python-multipart`; a raw stream is simpler and easier to bound.
- **Writing suppressions into the uploaded tree** -- rejected: invisible to the user, lost on delete.
- **Deleting the workspace after each audit** -- rejected: retry/resume and re-audit need the source.

## Consequences

- New settings: `UPLOAD_DIR`, `MAX_UPLOAD_MB`, `MAX_UPLOAD_FILES`, `MAX_UPLOAD_UNPACKED_MB`.
- `SOURCE_ROOTS` may now be empty while `UPLOAD_DIR` is set (uploads only).
- Tests: archive attacks, limits, isolation, delete-cleans-up, triage round trip, MCP explain.
