"""
investigation_graph.py
----------------------
LangGraph StateGraph definition for Splunk Sentinel.

Current graph (Phase 4 - Triage + Reconstruction + Parallel Enrichment + Synthesis):
  START -> triage_agent -> (conditional) -> reconstruction_agent -> (conditional)
                                         -> END (UNKNOWN / low-confidence / error)

  reconstruction_agent -> [threat_intel_agent, ttp_agent] (parallel fan-out)
  threat_intel_agent ->
                        synthesis_agent -> END
  ttp_agent ->
"""

import logging
from typing import Union, Literal

from langgraph.graph import END, START, StateGraph
from langgraph.constants import Send

from app.agents.synthesis_agent import synthesis_agent
from app.agents.threat_intel_agent import threat_intel_agent
from app.agents.ttp_agent import ttp_agent
from app.agents.reconstruction_agent import reconstruction_agent
from app.agents.triage_agent import triage_agent
from app.agents.report_agent import report_agent
from app.models.state import AgentState

logger = logging.getLogger(__name__)


def _route_after_triage(
    state: AgentState,
) -> Literal["reconstruction_agent", "__end__"]:
    """Existing routing — keep unchanged."""
    investigation_id = state.get("investigation_id", "unknown")
    if state.get("error"):
        logger.info("[%s] Routing to END — triage error", investigation_id)
        return END
    if state.get("attack_classification") == "UNKNOWN":
        logger.info("[%s] Routing to END — UNKNOWN", investigation_id)
        return END
    if state.get("classification_confidence", 0) < 0.5:
        logger.info("[%s] Routing to END — low confidence", investigation_id)
        return END
    logger.info(
        "[%s] Routing to reconstruction_agent", investigation_id
    )
    return "reconstruction_agent"


def _route_after_reconstruction(
    state: AgentState,
) -> Union[list[Send], str]:
    """
    Fan out to ThreatIntelAgent and TTPAgent in parallel.
    Skip both if reconstruction errored or classification is UNKNOWN.
    """
    investigation_id = state.get("investigation_id", "unknown")

    if state.get("error"):
        logger.info(
            "[%s] Routing to END — reconstruction error",
            investigation_id,
        )
        return END

    if state.get("attack_classification") == "UNKNOWN":
        logger.info(
            "[%s] Routing to END — UNKNOWN after reconstruction",
            investigation_id,
        )
        return END

    logger.info(
        "[%s] Fan-out: routing to threat_intel_agent + ttp_agent "
        "in parallel",
        investigation_id,
    )
    return [
        Send("threat_intel_agent", state),
        Send("ttp_agent", state),
    ]


def _build_graph() -> StateGraph:
    graph = StateGraph(AgentState)

    # Register all nodes
    graph.add_node("triage_agent", triage_agent)

    async def _reconstruction_node(state, config):
        callback = config.get("configurable", {}).get("progress_callback")
        return await reconstruction_agent(state, progress_callback=callback)

    graph.add_node("reconstruction_agent", _reconstruction_node)
    graph.add_node("threat_intel_agent", threat_intel_agent)
    graph.add_node("ttp_agent", ttp_agent)
    graph.add_node("synthesis_agent", synthesis_agent)
    graph.add_node("report_agent", report_agent)

    # Wire edges
    graph.add_edge(START, "triage_agent")

    graph.add_conditional_edges(
        "triage_agent",
        _route_after_triage,
        {
            "reconstruction_agent": "reconstruction_agent",
            END: END,
        },
    )

    graph.add_conditional_edges(
        "reconstruction_agent",
        _route_after_reconstruction,
    )

    # Both parallel agents converge into synthesis_agent
    graph.add_edge("threat_intel_agent", "synthesis_agent")
    graph.add_edge("ttp_agent", "synthesis_agent")

    # SynthesisAgent routes to report_agent
    graph.add_edge("synthesis_agent", "report_agent")
    graph.add_edge("report_agent", END)

    return graph


compiled_graph = _build_graph().compile()
logger.info(
    "Investigation graph compiled "
    "(Phase 4 — triage + reconstruction + parallel intel + synthesis)."
)
