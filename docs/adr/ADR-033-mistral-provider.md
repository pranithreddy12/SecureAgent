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

## Not claimed

Nobody has run a live Mistral review yet; the new provider is covered by unit tests with a fake
transport (`tests/test_llm_review.py`), the same way the Anthropic path already was before any live
run. Redaction, quote verification, caching and the "never changes status/gate" guarantee are
provider-agnostic and apply identically to both.
