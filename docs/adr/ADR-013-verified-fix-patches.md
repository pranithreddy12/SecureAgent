# ADR-013: Verified fix patches

- **Date:** 2026-10-11
- **Status:** Accepted

## Context

Reporting a flaw is half the job; a developer still has to write the fix. For a small set of findings
the correct fix is a one-line, local, well-understood edit. Offering those as patches closes the loop
-- but an auto-fixer that silently breaks code or claims success without checking would be worse than
none.

## Decision

`app/analysis/fixes.py` proposes **deterministic** patches for: weak hash (MD5/SHA-1 -> SHA-256),
disabled TLS verification, `yaml.load` -> `yaml.safe_load`, debug flag, CSRF disabled, JWT
verification disabled, and hardcoded Python secrets (-> `os.environ[...]`, adding `import os`).

A patch is **verified** only if, applied to a private copy of the file, (1) it still parses, (2) a
re-scan shows fewer findings of every fixed type, and (3) no finding type appears that was not there
before. Unverified patches are shown with the reason and are never written.

Delivery:
- `secureagent fix PATH` prints reasons, caveats and unified diffs (dry run); `--apply` writes
  verified patches only, atomically, and only if the file is byte-identical to what was analysed.
- MCP tool `suggest_fixes` returns the diffs and never writes.
- Symlinks and paths outside the root are skipped; line endings (CRLF) are preserved.

Honesty rules:
- "Verified" means *the finding is gone and the file is well-formed*, **not** that behaviour is
  preserved. Every change carries a caveat stating what to check (digests change, certificates must
  be valid, the secret is still in git history and must be rotated).
- No LLM generates patches; there is no free-form rewriting.

## Alternatives

- **LLM-generated patches** -- cover more, but are not reproducible and can change semantics; could
  later be offered as *suggestions* behind the same verification gate.
- **Run the project's tests to verify** -- stronger, but requires executing untrusted code, which the
  scanner never does (ADR-008).

## Consequences

- Injection, IDOR and authorization findings are deliberately not auto-fixed: the right fix depends on
  the application (what is the ownership rule? which parameter binding?).
- Fix verification is single-file; a fix whose effect depends on other files is not attempted.
