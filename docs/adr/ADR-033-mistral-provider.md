# ADR-033: Mistral as a second LLM provider

- **Date:** 2026-10-14
- **Status:** Accepted (owner: "for now i need a mistral as a llm option also")

## Context

The opt-in AI review/narrative layer (`app/analysis/llm_review.py`, ADR-017/018) talked to the
Anthropic Messages API only: a fixed URL, `x-api-key` header, and `{"content": [...]}` response shape
hardcoded into `Reviewer.review`/`narrate`. `Settings.llm_provider` already existed but was never read.

## Decision

Add a small provider table (`PROVIDERS: dict[str, ProviderSpec]`) holding, per provider, its API URL
(via a dedicated transport function), default model, auth header, request-payload shape and
response-text extractor. `Reviewer` gains a `provider` field and resolves its model/transport from that
table when not given explicitly; `review()`, `narrate()` and `parse_verdict()` build the request and
read the response through it instead of Anthropic-shaped code. `api_key_from_env()` takes the provider
and reads the matching env var.

Wired `settings.llm_provider` into `app/pipeline/stages.py::_ai_settings` (the opt-in pipeline stages)
and added `secureagent review --provider {anthropic,mistral}` to the CLI. `LLM_PROVIDER=mistral` +
`MISTRAL_API_KEY` is now enough to switch the whole opt-in AI layer over; `LLM_MODEL` empty picks the
provider's default (`mistral-large-latest`).

Mistral uses the OpenAI-compatible chat-completions shape (`Authorization: Bearer <key>`, `messages`
with a `system` role, `choices[0].message.content`), which is why the abstraction is a per-provider
payload/header/extractor rather than a single Anthropic-shaped `Reviewer`.

## Live run (2026-10-14)

Ran `secureagent review` against `benchmark/corpus/py_injection.py` with a real `MISTRAL_API_KEY`
(the key was never seen by the assistant: read from the user's own environment variable store inside
one shell call, never echoed or logged). Three model ids were tried on the owner's account:

| Model | Result |
|---|---|
| `mistral-large-latest` / a newer large alias | `403 tier_not_allowed` -- needs a paid plan |
| `mistral-small-latest` | tier-allowed, but `429 rate_limited` on every attempt, minutes apart |
| `codestral-latest` | **worked** |

`codestral-latest` returned a genuine verdict end to end: `TRUE POSITIVE 90% code_injection` on the
file's `eval("themes." + _theme())` cookie-driven code-injection case, with its quote verified against
the code actually sent (not downgraded to `unclear`), on the first try. Redaction, prompt construction,
response parsing and the "never changes status/gate" behaviour all held against a live response, not
just the fake-transport tests.

## Live run through the actual product (2026-10-14)

The run above used the bare `secureagent review` CLI. Separately, restarted the backend
(`docker compose up -d --build postgres backend`) with `LLM_PROVIDER=mistral`,
`LLM_MODEL=codestral-latest` in `.env`, and ran a full audit through the real pipeline: registered a
throwaway user, created a project at `/workspace/py_injection` (the same corpus fixture, mounted
read-only under `SOURCE_ROOTS`), authorized it, and started an audit with `ai_review: true` via
`POST /api/projects/{id}/audits` -- the actual `ai_validator`/`ai_narrative` LangGraph stages, not a
direct call into `Reviewer`.

Result: `status: completed`, `ai: {enabled: true, model: codestral-latest, reviewed: 15, problems:
[]}`. All 15 deterministic findings got a live AI verdict (13 `true_positive` at 0.8-0.9 confidence on
the genuine planted flaws, correctly matching), and the AI-written executive summary was accepted
(passed `acceptable_narrative`'s banned-claims and shape checks) and is grounded in the real finding
counts and locations -- no invented vulnerabilities, no "confirmed exploited" language. Status and
severity on every finding were untouched by the AI stage, as designed.

## Not claimed

This is one live run, on one account, on one finding type, with a free-tier key. It establishes that
the provider abstraction genuinely talks to Mistral's real API (payload shape, auth header and
response parsing are all correct), not that every model id or every finding type has been tried
live, and not that accuracy on this provider has been measured the way the deterministic scanner's
has. `MISTRAL_DEFAULT_MODEL` is left as `mistral-large-latest` (the model Mistral documents as its
flagship) rather than changed to match one account's current tier.
