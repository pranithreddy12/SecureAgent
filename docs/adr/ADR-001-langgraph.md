# ADR-001: LangGraph for multi-agent orchestration

- **Date:** 2026-10-02
- **Status:** Accepted

## Context
The PPT specifies LangChain / LangGraph. The audit is a fixed, mostly linear pipeline
with one conditional branch (findings present?), needs a shared typed state, and must
be resumable after a failed stage.

## Decision
Use LangGraph `StateGraph` with a `TypedDict` `AuditState`. Agents are graph nodes.
LangChain is used only for the optional LLM chat-model interface and structured
output. Stage outputs are persisted to PostgreSQL by our own runner after each node
(resumability lives in our tables, not in a LangGraph checkpointer — see ADR-005).

## Alternatives
- Plain async function pipeline — simpler, but departs from the specified stack.
- LangGraph Postgres checkpointer — adds a dependency and a second persistence model
  for the same data.
- CrewAI / AutoGen — not in the specification.

## Consequences
- Matches the academic architecture directly (graph = methodology diagram).
- The LLM never controls graph routing; routing is deterministic.
