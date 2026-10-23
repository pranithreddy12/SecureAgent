"""LangGraph-shaped StateGraph.

Uses `langgraph` when installed (ADR-001). Falls back to a tiny sequential runner with the
same node/edge/conditional API so tests and the CLI extra stay installable without the
orchestration package.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Hashable
from typing import Any

START = "__start__"
END = "__end__"

NodeFn = Callable[[dict], Awaitable[dict]]
Router = Callable[[dict], Hashable]


class _Compiled:
    def __init__(
        self,
        nodes: dict[str, NodeFn],
        edges: dict[str, str],
        conditionals: dict[str, tuple[Router, dict[Hashable, str]]],
        start: str,
    ) -> None:
        self.nodes = nodes
        self.edges = edges
        self.conditionals = conditionals
        self.start = start

    async def ainvoke(
        self,
        state: dict[str, Any],
        on_step: Callable[[dict[str, Any], str], Awaitable[None]] | None = None,
    ) -> dict[str, Any]:
        """``on_step(state, node_name)`` runs after each node completes, so a caller can persist
        progress incrementally (a live audit can take minutes; without this the UI would show
        nothing until the whole run finishes). Optional and additive -- every existing caller is
        unaffected."""
        current: str | None = self.start
        while current and current != END:
            fn = self.nodes[current]
            update = await fn(state)
            if update:
                state.update(update)
            if on_step is not None:
                await on_step(state, current)
            if current in self.conditionals:
                router, mapping = self.conditionals[current]
                nxt = mapping.get(router(state), END)
                current = None if nxt == END else str(nxt)
            else:
                nxt = self.edges.get(current, END)
                current = None if nxt == END else nxt
        return state


class StateGraph:
    def __init__(self, _schema: type | None = None) -> None:
        self._nodes: dict[str, NodeFn] = {}
        self._edges: dict[str, str] = {}
        self._conditionals: dict[str, tuple[Router, dict[Hashable, str]]] = {}
        self._start: str = ""

    def add_node(self, name: str, fn: NodeFn) -> None:
        self._nodes[name] = fn

    def add_edge(self, src: str, dst: str) -> None:
        if src == START:
            self._start = dst
        else:
            self._edges[src] = dst

    def add_conditional_edges(self, src: str, router: Router, mapping: dict[Hashable, str]) -> None:
        self._conditionals[src] = (router, mapping)

    def compile(self) -> _Compiled:
        return _Compiled(self._nodes, self._edges, self._conditionals, self._start)


def load_state_graph():
    try:
        from langgraph.graph import END as LG_END
        from langgraph.graph import START as LG_START
        from langgraph.graph import StateGraph as LGStateGraph

        return LGStateGraph, LG_START, LG_END
    except ImportError:
        return StateGraph, START, END
