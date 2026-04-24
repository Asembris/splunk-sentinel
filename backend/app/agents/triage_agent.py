"""
triage_agent.py
---------------
LangGraph node: TriageAgent

Responsibilities:
  1. Pull raw telemetry stats from Splunk (attack window, top source IPs).
  2. Build a structured context string from those stats.
  3. Call gpt-4o-mini (JSON mode) with a strict SOC-analyst system prompt.
  4. Parse and validate the LLM response.
  5. Enforce escalation when confidence < 0.5.
  6. Return an updated AgentState.

This node is intentionally side-effect-free with respect to Splunk writes;
all writes are handled by downstream agents or the report node.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from langsmith import traceable
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from app.models.state import AgentState
from app.tools.splunk_tools import SplunkClient
from app.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LLM client — shared across invocations (thread-safe singleton)
# ---------------------------------------------------------------------------

_LLM = ChatOpenAI(
    model="gpt-4o-mini",
    temperature=0,
    api_key=settings.OPENAI_API_KEY,
)

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are a senior SOC analyst. Given telemetry statistics from a security "
    "incident, classify the attack type and assess severity. Be precise. "
    "Base your assessment only on the data provided. "
    "Do not hallucinate indicators not present in the data. "
    "\n\n"
    "Respond with valid JSON matching this exact schema:\n"
    "{{\n"
    '  "attack_classification": "APT" | "RANSOMWARE" | "INSIDER" | "DDOS" | "UNKNOWN",\n'
    '  "classification_confidence": <float 0.0–1.0>,\n'
    '  "triage_summary": "<2-3 sentence human-readable assessment>",\n'
    '  "escalate_to_human": <true|false>,\n'
    '  "reasoning": "<brief explanation of your classification decision>"\n'
    "}}"
)

# ---------------------------------------------------------------------------
# Helper: build context string from Splunk telemetry
# ---------------------------------------------------------------------------


def _build_sanitized_context(attack_window: dict, top_ips: list[dict]) -> str:
    """
    Construct a sanitized context string for the LLM that omits specific IP 
    addresses to comply with security tracing requirements.
    """
    ip_stats = "\n".join(
        f"  - Source IP #{i + 1}  →  {row['event_count']:,} events"
        for i, row in enumerate(top_ips)
    ) or "  (no source IPs found)"

    return (
        f"=== ATTACK WINDOW ===\n"
        f"  First activity : {attack_window.get('start', 'unknown')}\n"
        f"  Last activity  : {attack_window.get('end', 'unknown')}\n"
        f"  Peak hour      : {attack_window.get('peak_hour', 'unknown')} "
        f"({attack_window.get('peak_count', 0):,} events)\n"
        f"  Total events   : {attack_window.get('total_events', 0):,}\n"
        f"\n"
        f"=== TOP SOURCE IP STATISTICS ===\n"
        f"{ip_stats}\n"
        f"\n"
        f"Dataset: BOTS v3 (Boss of the SOC v3) — a realistic APT attack scenario.\n"
    )


# ---------------------------------------------------------------------------
# Helper: parse and validate LLM JSON response
# ---------------------------------------------------------------------------


def _parse_llm_response(raw: str) -> dict[str, Any]:
    """
    Parse the raw JSON string from the LLM into a validated Python dict.

    Fills in safe defaults for any missing or malformed fields so a partial
    LLM response can never crash the graph.

    Args:
        raw: Raw JSON string returned by the LLM.

    Returns:
        Dict with all expected triage fields, filled with defaults where needed.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.error("LLM returned invalid JSON: %s | raw=%r", exc, raw[:200])
        data = {}

    # Normalise and apply defaults
    valid_classifications = {"APT", "RANSOMWARE", "INSIDER", "DDOS", "UNKNOWN"}
    classification = str(data.get("attack_classification", "UNKNOWN")).upper()
    if classification not in valid_classifications:
        logger.warning(
            "Unexpected attack_classification value '%s'; defaulting to UNKNOWN",
            classification,
        )
        classification = "UNKNOWN"

    try:
        confidence = float(data.get("classification_confidence", 0.0))
        confidence = max(0.0, min(1.0, confidence))  # clamp to [0, 1]
    except (TypeError, ValueError):
        confidence = 0.0

    return {
        "attack_classification": classification,
        "classification_confidence": confidence,
        "triage_summary": str(data.get("triage_summary", "Insufficient data for triage.")),
        "escalate_to_human": bool(data.get("escalate_to_human", False)),
        "reasoning": str(data.get("reasoning", "")),
    }


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------


@traceable(
    name="TriageAgent",
    run_type="chain",
    tags=["triage", "splunk-sentinel"],
)
async def triage_agent(state: AgentState) -> AgentState:
    """
    LangGraph node — TriageAgent.

    Executes the initial investigation triage:
      - Queries Splunk for attack window and top source IPs.
      - Calls gpt-4o-mini with JSON mode to classify the attack.
      - Enforces escalation when confidence < 0.5.
      - Appends all executed SPL queries to spl_audit_log in the state.

    Args:
        state: Current AgentState flowing through the LangGraph graph.

    Returns:
        Updated AgentState with triage fields populated.
        On any unrecoverable failure, sets ``state["error"]`` and returns
        without crashing the graph.
    """
    investigation_id = state.get("investigation_id", "unknown")
    logger.info("[%s] TriageAgent starting …", investigation_id)

    # ── Step 1: Initialise Splunk client ────────────────────────────────────
    try:
        splunk = SplunkClient()
    except Exception as exc:
        logger.error("[%s] Failed to connect to Splunk: %s", investigation_id, exc)
        return {
            **state,
            "error": f"TriageAgent: Splunk connection failed — {exc}",
            "escalate_to_human": True,
        }

    # ── Step 2: Pull telemetry from Splunk ──────────────────────────────────
    attack_window: dict = {}
    top_ips: list[dict] = []

    try:
        attack_window = await splunk.get_attack_window()
        logger.info("[%s] Attack window: %s", investigation_id, attack_window)
    except Exception as exc:
        logger.error("[%s] get_attack_window failed: %s", investigation_id, exc)
        attack_window = {
            "start": "unknown", "end": "unknown",
            "peak_hour": "unknown", "peak_count": 0, "total_events": 0,
        }

    try:
        top_ips = await splunk.get_top_source_ips(top_n=10)
        logger.info("[%s] Top source IPs: %d entries", investigation_id, len(top_ips))
    except Exception as exc:
        logger.error("[%s] get_top_source_ips failed: %s", investigation_id, exc)
        top_ips = []

    # ── Step 3: Build LLM context ───────────────────────────────────────────
    context = _build_sanitized_context(attack_window, top_ips)
    logger.debug("[%s] LLM context:\n%s", investigation_id, context)

    # ── Step 4: Call gpt-4o-mini (Traced) ──────────────────────────────────
    try:
        # Use RunnableSequence for LangSmith named span
        prompt = ChatPromptTemplate.from_messages([
            ("system", _SYSTEM_PROMPT),
            ("user", "{context}"),
        ])
        
        chain = (prompt | _LLM | JsonOutputParser()).with_config({
            "run_name": "triage_llm_call",
            "metadata": {
                "investigation_id": investigation_id,
                "attack_window_start": attack_window.get("start"),
                "attack_window_end": attack_window.get("end"),
                "attack_window_peak": attack_window.get("peak_hour"),
                "top_source_ip_count": len(top_ips),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        })
        
        parsed = await chain.ainvoke({"context": context})
    except Exception as exc:
        logger.error("[%s] LLM call failed: %s", investigation_id, exc)
        return {
            **state,
            "attack_window": attack_window,
            "top_source_ips": top_ips,
            "error": f"TriageAgent: LLM call failed — {exc}",
            "escalate_to_human": True,
            "spl_audit_log": list(state.get("spl_audit_log", [])) + splunk.audit_log,
        }

    # ── Step 5: Enforce escalation threshold ────────────────────────────────
    # (LLM response already parsed into dict by JsonOutputParser)
    parsed["escalate_to_human"] = parsed["classification_confidence"] < 0.5

    if parsed["escalate_to_human"]:
        logger.warning(
            "[%s] Low confidence (%.2f) — escalating to human review.",
            investigation_id,
            parsed["classification_confidence"],
        )

    # ── Step 7: Update audit log ────────────────────────────────────────────
    existing_audit = list(state.get("spl_audit_log", []))
    updated_audit = existing_audit + splunk.audit_log

    # ── Step 8: Build updated state ─────────────────────────────────────────
    updated_state: AgentState = {
        **state,
        "attack_window": attack_window,
        "top_source_ips": top_ips,
        "attack_classification": parsed["attack_classification"],
        "classification_confidence": parsed["classification_confidence"],
        "triage_summary": parsed["triage_summary"],
        "escalate_to_human": parsed["escalate_to_human"],
        "confidence_scores": {
            **state.get("confidence_scores", {}),
            "triage": parsed["classification_confidence"],
        },
        "spl_audit_log": updated_audit,
        "error": None,
    }

    logger.info(
        "[%s] TriageAgent complete | classification=%s | confidence=%.2f | escalate=%s",
        investigation_id,
        parsed["attack_classification"],
        parsed["classification_confidence"],
        parsed["escalate_to_human"],
    )
    return updated_state
