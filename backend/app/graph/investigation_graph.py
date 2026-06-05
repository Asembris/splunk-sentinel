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
import os
from typing import Union, Literal

from langgraph.graph import END, START, StateGraph
from langgraph.constants import Send
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

from app.agents.synthesis_agent import synthesis_agent
from app.agents.threat_intel_agent import threat_intel_agent
from app.agents.ttp_agent import ttp_agent
from app.agents.reconstruction_agent import reconstruction_agent
from app.agents.triage_agent import triage_agent
from app.agents.report_agent import report_agent
from app.models.state import AgentState
import asyncio
import time
from app.services.slo_engine import get_monitor, cleanup_monitor, DEFAULT_POLICY

logger = logging.getLogger(__name__)


def _route_after_triage(
    state: AgentState,
) -> Literal["reconstruction_agent", "report_agent"]:
    """Existing routing — updated to ensure report_agent always runs."""
    investigation_id = state.get("investigation_id", "unknown")
    if state.get("error"):
        logger.info("[%s] Routing to report_agent — triage error", investigation_id)
        return "report_agent"
    if state.get("attack_classification") == "UNKNOWN":
        logger.info("[%s] Routing to report_agent — UNKNOWN", investigation_id)
        return "report_agent"
    if state.get("classification_confidence", 0) < 0.5:
        logger.info("[%s] Routing to report_agent — low confidence", investigation_id)
        return "report_agent"
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
            "[%s] Routing to report_agent — reconstruction error",
            investigation_id,
        )
        return "report_agent"

    if state.get("attack_classification") == "UNKNOWN":
        logger.info(
            "[%s] Routing to report_agent — UNKNOWN after reconstruction",
            investigation_id,
        )
        return "report_agent"

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

    def make_timed_agent(agent_fn, agent_name: str, timeout_seconds: int):
        """
        Wraps an agent function with:
        1. SLO timing (records start/end)
        2. asyncio timeout (hard limit)
        3. Graceful degradation on timeout
        """
        async def timed_agent(state, config=None):
            investigation_id = state.get("investigation_id", "unknown")
            monitor = get_monitor(investigation_id)
            monitor.record_agent_start(agent_name)

            logger.info(
                "[SLO] %s | %s starting | budget=%ds",
                investigation_id,
                agent_name,
                timeout_seconds,
            )

            try:
                # All agents now support (state, config) signature
                result = await asyncio.wait_for(
                    agent_fn(state, config),
                    timeout=timeout_seconds,
                )
                monitor.record_agent_end(agent_name)
                return result

            except asyncio.TimeoutError:
                monitor.record_agent_end(agent_name)
                logger.error(
                    "[SLO] %s | %s TIMEOUT after %ds — "
                    "returning partial state with escalation flag",
                    investigation_id,
                    agent_name,
                    timeout_seconds,
                )
                # Preserve all upstream state — only add timeout markers.
                # A minimal final_report ensures report_agent and the frontend
                # receive a structured degraded response instead of null fields.
                partial_report = state.get("final_report") or {
                    "investigation_id": investigation_id,
                    "generated_at": __import__("datetime").datetime.now(
                        __import__("datetime").timezone.utc
                    ).isoformat(),
                    "executive_summary": (
                        f"Investigation incomplete — {agent_name} timed out "
                        f"after {timeout_seconds}s. Manual analyst review required."
                    ),
                    "key_findings": [],
                    "recommended_actions": [],
                    "mitre_techniques_used": [],
                    "investigation_confidence": 0.0,
                    "containment_plan": {"phases": []},
                }
                return {
                    **state,
                    "error": f"Agent {agent_name} timed out after {timeout_seconds}s",
                    "escalate_to_human": True,
                    "final_report": partial_report,
                }

        timed_agent.__name__ = f"timed_{agent_name}"
        return timed_agent

    # Apply to each agent node
    graph.add_node(
        "triage_agent",
        make_timed_agent(
            triage_agent,
            "triage_agent",
            DEFAULT_POLICY.agent_timeouts["triage_agent"],
        )
    )

    async def _reconstruction_node(state, config):
        callback = config.get("configurable", {}).get("progress_callback")
        return await reconstruction_agent(state, progress_callback=callback)

    graph.add_node(
        "reconstruction_agent",
        make_timed_agent(
            _reconstruction_node,
            "reconstruction_agent",
            DEFAULT_POLICY.agent_timeouts["reconstruction_agent"],
        )
    )

    graph.add_node(
        "threat_intel_agent",
        make_timed_agent(
            threat_intel_agent,
            "threat_intel_agent",
            DEFAULT_POLICY.agent_timeouts["threat_intel_agent"],
        )
    )

    graph.add_node(
        "ttp_agent",
        make_timed_agent(
            ttp_agent,
            "ttp_agent",
            DEFAULT_POLICY.agent_timeouts["ttp_agent"],
        )
    )

    graph.add_node(
        "synthesis_agent",
        make_timed_agent(
            synthesis_agent,
            "synthesis_agent",
            DEFAULT_POLICY.agent_timeouts["synthesis_agent"],
        )
    )

    graph.add_node(
        "report_agent",
        make_timed_agent(
            report_agent,
            "report_agent",
            DEFAULT_POLICY.agent_timeouts["report_agent"],
        )
    )

    # Wire edges
    graph.add_edge(START, "triage_agent")

    graph.add_conditional_edges(
        "triage_agent",
        _route_after_triage,
        {
            "reconstruction_agent": "reconstruction_agent",
            "report_agent": "report_agent",
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


_checkpointer_context = None
_checkpointer: AsyncSqliteSaver | None = None
_compiled_graph = None


async def init_graph():
    global _checkpointer_context, _checkpointer, _compiled_graph
    if _compiled_graph is not None:
        return _compiled_graph

    db_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "checkpoints.db"
    )
    _checkpointer_context = AsyncSqliteSaver.from_conn_string(db_path)
    _checkpointer = await _checkpointer_context.__aenter__()
    _compiled_graph = _build_graph().compile(checkpointer=_checkpointer)
    logger.info(
        "Investigation graph compiled "
        "(Phase 4 — triage + reconstruction + parallel intel + synthesis)."
    )
    return _compiled_graph


def get_graph():
    if _compiled_graph is None:
        raise RuntimeError("Graph not initialized. Call init_graph() first.")
    return _compiled_graph
