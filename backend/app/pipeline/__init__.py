"""Source-only audit pipeline: agents orchestrated as a LangGraph workflow (ADR-016).

Every agent reads and writes *persisted* artifacts (reconnaissance results, findings, stage state),
not in-memory objects, so a failed audit can resume from the first incomplete stage.
"""
