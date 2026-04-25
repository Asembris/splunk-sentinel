"""
investigation_graph.py
----------------------
LangGraph StateGraph definition for Splunk Sentinel.

Current graph (Phase 1 — Triage only):
  START -> triage_agent -> END

Routing rules:
  - If state["error"] is not None  →  route to END immediately.
  - If state["escalate_to_human"]  →  route to END (human review required).
  - Otherwise                      →  route to END (future nodes will be
                                      inserted here in later phases).

To add a new agent in a later phase, register it with
``graph.add_node("new_agent", new_agent_fn)`` and update
``_route_after_triage`` to return its name instead of END.
"""

from __future__ import annotations

import logging
from typing import Literal

from langgraph.graph import END, START, StateGraph

from app.agents.triage_agent import triage_agent
from app.models.state import AgentState

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Conditional routing
# ---------------------------------------------------------------------------


def _route_after_triage(
    state: AgentState,
) -> Literal["__end__"]:
    """
    Determine the next node after TriageAgent completes.

    Routing table (Phase 1):
    ┌─────────────────────────────────────┬──────────────┐
    │ Condition                           │ Next node    │
    ├─────────────────────────────────────┼──────────────┤
    │ state["error"] is not None          │ END          │
    │ state["escalate_to_human"] is True  │ END          │
    │ (default — future phases add here)  │ END          │
    └─────────────────────────────────────┴──────────────┘

    Args:
        state: AgentState after triage_agent has run.

    Returns:
        The name of the next LangGraph node, or ``END``.
    """
    investigation_id = state.get("investigation_id", "unknown")

    if state.get("error") is not None:
        logger.warning(
            "[%s] Routing to END — error detected: %s",
            investigation_id,
            state["error"],
        )
        return END

    if state.get("escalate_to_human"):
        logger.info(
            "[%s] Routing to END — escalate_to_human=True (confidence=%.2f)",
            investigation_id,
            state.get("classification_confidence", 0.0),
        )
        return END

    # Phase 1: no further nodes yet — always terminate after triage.
    # Phase 2 will return "reconstruction_agent" here, etc.
    logger.info(
        "[%s] Routing to RECONSTRUCTION — confidence=%.2f",
        investigation_id,
        state.get("classification_confidence", 0.0),
    )
    return END


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def _build_graph() -> StateGraph:
    """
    Construct and wire the LangGraph StateGraph for the investigation pipeline.

    Returns:
        A compiled ``StateGraph`` instance.
    """
    graph = StateGraph(AgentState)

    # ── Register nodes ───────────────────────────────────────────────────────
    graph.add_node("triage_agent", triage_agent)
    # Future nodes registered here:
    # graph.add_node("reconstruction_agent", reconstruction_agent)
    # graph.add_node("patient_zero_agent", patient_zero_agent)
    # graph.add_node("blast_radius_agent", blast_radius_agent)
    # graph.add_node("threat_intel_agent", threat_intel_agent)
    # graph.add_node("ttp_agent", ttp_agent)
    # graph.add_node("report_agent", report_agent)

    # ── Wire edges ───────────────────────────────────────────────────────────
    graph.add_edge(START, "triage_agent")
    graph.add_edge("triage_agent", END)

    return graph


# ---------------------------------------------------------------------------
# Exported compiled graph
# ---------------------------------------------------------------------------

compiled_graph = _build_graph().compile()

logger.info("Investigation graph compiled successfully (Phase 1 — triage only).")
