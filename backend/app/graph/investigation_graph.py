"""
investigation_graph.py
----------------------
LangGraph StateGraph definition for Splunk Sentinel.

Current graph (Phase 2 — Triage + Reconstruction):
  START -> triage_agent -> (conditional) -> reconstruction_agent -> END
                                        \-> END (UNKNOWN / low-confidence / error)

Routing rules after TriageAgent:
  - state["error"] is not None       →  route to END immediately
  - classification == "UNKNOWN"      →  route to END (insufficient signal)
  - confidence < 0.5                 →  route to END (low confidence)
  - otherwise                        →  route to reconstruction_agent

To add further agents in later phases, register them with
``graph.add_node(...)`` and update ``_route_after_triage`` accordingly.
"""

from __future__ import annotations

import logging
from typing import Literal

from langgraph.graph import END, START, StateGraph

from app.agents.reconstruction_agent import reconstruction_agent
from app.agents.triage_agent import triage_agent
from app.models.state import AgentState

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Conditional routing
# ---------------------------------------------------------------------------


def _route_after_triage(
    state: AgentState,
) -> Literal["reconstruction_agent", "__end__"]:
    """
    Determine the next node after TriageAgent completes.

    Routing table (Phase 2):
    ┌──────────────────────────────────────────┬──────────────────────────┐
    │ Condition                                │ Next node                │
    ├──────────────────────────────────────────┼──────────────────────────┤
    │ state["error"] is not None               │ END                      │
    │ classification == "UNKNOWN"              │ END                      │
    │ confidence < 0.5                         │ END (low confidence)     │
    │ (default — confident known threat)       │ reconstruction_agent     │
    └──────────────────────────────────────────┴──────────────────────────┘

    Args:
        state: AgentState after triage_agent has run.

    Returns:
        The name of the next LangGraph node, or END.
    """
    investigation_id = state.get("investigation_id", "unknown")

    if state.get("error") is not None:
        logger.info(
            "[%s] Routing to END — triage error present: %s",
            investigation_id,
            state["error"],
        )
        return END

    classification = state.get("attack_classification", "UNKNOWN")
    if classification == "UNKNOWN":
        logger.info(
            "[%s] Routing to END — classification is UNKNOWN",
            investigation_id,
        )
        return END

    confidence = state.get("classification_confidence", 0.0)
    if confidence < 0.5:
        logger.info(
            "[%s] Routing to END — confidence below 0.5 (%.2f)",
            investigation_id,
            confidence,
        )
        return END

    logger.info(
        "[%s] Routing to reconstruction_agent | classification=%s | confidence=%.2f",
        investigation_id,
        classification,
        confidence,
    )
    return "reconstruction_agent"


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

    # ── Register nodes ────────────────────────────────────────────────────────
    graph.add_node("triage_agent", triage_agent)

    async def _reconstruction_node(state, config):
        callback = config.get("configurable", {}).get("progress_callback")
        return await reconstruction_agent(state, progress_callback=callback)

    graph.add_node("reconstruction_agent", _reconstruction_node)
    # Future nodes registered here:
    # graph.add_node("threat_intel_agent", threat_intel_agent)
    # graph.add_node("ttp_agent", ttp_agent)
    # graph.add_node("report_agent", report_agent)

    # ── Wire edges ────────────────────────────────────────────────────────────
    graph.add_edge(START, "triage_agent")
    graph.add_conditional_edges(
        "triage_agent",
        _route_after_triage,
        {
            "reconstruction_agent": "reconstruction_agent",
            END: END,
        },
    )
    graph.add_edge("reconstruction_agent", END)

    return graph


# ---------------------------------------------------------------------------
# Exported compiled graph
# ---------------------------------------------------------------------------

compiled_graph = _build_graph().compile()

logger.info(
    "Investigation graph compiled successfully "
    "(Phase 2 — triage + reconstruction)."
)
