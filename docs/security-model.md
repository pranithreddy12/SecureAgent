# SecureAgent – Security Model

Status: **Design (Phase 0)**. Every rule here must have an automated test.

## 1. Authorization Gate

- A target can be audited only if its most recent `AuthorizationRecord` has
  `confirmed=true` and was recorded **after** the last change to the target's URL or
  scope.
- Required statement: *"I confirm that I am authorized to perform security testing
  against this target."*
- Checked at three layers: the API (`/audits/{id}/start`), the workflow gate node,
  and inside every tool call (defence in depth).

## 2. Target Safety Validation

Implemented in `app/security/target_validation.py`.

1. Scheme must be `http` or `https`; no userinfo in the URL; valid port.
2. The hostname is resolved and **every** resolved address is checked. By default
   these are blocked: loopback, private (RFC 1918 / ULA), link-local, unspecified,
   multicast, reserved, carrier-grade NAT, and cloud metadata addresses.
3. Hostnames such as `localhost` and `*.localhost` are blocked before resolution.
4. `ALLOW_PRIVATE_TARGETS=true` relaxes rule 2 for private/loopback ranges **only**
   (for the local lab, e.g. Juice Shop). Cloud metadata addresses stay blocked
   regardless.
5. `TARGET_ALLOWLIST` (comma-separated hostnames), when set, restricts targets to
   those hosts only.
6. Scope: by default the target's own host with any path; optional path prefixes.
   Tools reject any URL outside the scope.
7. Re-validation at request time: every tool request re-resolves and re-checks the
   destination, and HTTP redirects are followed manually with each hop checked
   (mitigates DNS-rebinding and redirect-to-internal tricks).

## 3. Tool Safety

- No `shell=True` anywhere; subprocesses take an argv list built from validated
  values only. LLM-produced arguments are never passed through unvalidated.
- Every tool enforces: authorization, scope, timeout (`SCAN_TIMEOUT`,
  `MAX_SCAN_DURATION`), request rate limit, maximum pages/requests, output size cap,
  and cancellation.
- ZAP: API key required; context include-regex limited to the scope; conservative
  scan policy; ZAP API not published to the host.
- Nuclei: intrusive / DoS-type template tags excluded; rate limit and concurrency
  flags set; JSONL output parsed with size limits.
- Safe validation: non-destructive evidence collection only (see
  `docs/agent-workflow.md` §4.3).

## 4. Out of Scope by Design

The platform never implements: CAPTCHA/WAF/Cloudflare bypass, authentication or
authorization bypass, rate-limit evasion, credential theft, malware, persistence,
destructive exploitation, data exfiltration, denial of service, or privilege
escalation.

## 5. Application Security

- Passwords hashed with a slow adaptive algorithm (passlib/bcrypt or argon2);
  plaintext never stored or logged.
- JWT signed with `SECRET_KEY` from the environment; short expiry; httpOnly cookie,
  `SameSite=Lax`, `Secure` in production.
- Ownership checks on every resource; other users' resources return 404.
- Pydantic validation on all inputs; size limits on free-text fields.
- Secrets only in `.env` (git-ignored); `.env.example` holds placeholders.
- Evidence excerpts are size-capped and redact obvious secrets (tokens, passwords)
  before storage.
- CORS limited to `FRONTEND_ORIGIN`.

## 6. Honesty Rules for Findings

- Scanner output is *potential* until validated.
- CVE identifiers only from tool/template metadata — never generated.
- CVSS only when supplied with a vector/score from a reliable source.
- Severity is never inflated.
- Demo results are always labelled **DEMO / SIMULATED SECURITY AUDIT**.
