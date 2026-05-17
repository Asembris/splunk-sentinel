"""
SLO Enforcement Engine — Splunk Sentinel

Defines and enforces 4 production Service Level Objectives
for every autonomous investigation. Unlike passive monitoring
(LangSmith traces), this engine takes corrective action when
budgets are approached or breached.

SLO 1: Investigation time budget — 120 seconds total
SLO 2: Reconstruction token budget — 45,000 tokens
SLO 3: Confidence floor — 0.50 minimum after reconstruction
SLO 4: Per-agent timeouts — individual budgets per agent

Design: in-process enforcement via asyncio.wait_for()
Correct for single-machine deployment. No external queue
dependencies required at this scale.
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


# ── SLO Policy Definitions ───────────────────────────────────────────────────

@dataclass
class SLOPolicy:
    """
    Production SLO budgets for the investigation pipeline.
    All times in seconds. Tokens are estimated input tokens.
    """
    # SLO 1: Total investigation wall-clock time
    investigation_time_budget_seconds: int = 120

    # SLO 2: Reconstruction agent token budget (input tokens)
    # Average is ~40.6K — 45K gives 10% headroom
    reconstruction_token_budget: int = 45000

    # SLO 3: Minimum acceptable confidence after reconstruction
    # Below this threshold → force escalate_to_human = True
    confidence_floor: float = 0.50

    # SLO 4: Per-agent wall-clock time budgets (seconds)
    agent_timeouts: dict = field(default_factory=lambda: {
        "triage_agent":         45,
        "reconstruction_agent": 80,
        "threat_intel_agent":   20,
        "ttp_agent":            20,
        # 4 parallel LLM calls — wall time ~15s, 90s gives 6× headroom
        "synthesis_agent":      90,
        "report_agent":         30,
    })


# Singleton policy — used across the pipeline
DEFAULT_POLICY = SLOPolicy()


# ── SLO Monitor ──────────────────────────────────────────────────────────────

class SLOMonitor:
    """
    Tracks SLO compliance during a single investigation.
    Instantiated once per investigation_id.
    """

    def __init__(
        self,
        investigation_id: str,
        policy: SLOPolicy = DEFAULT_POLICY,
    ):
        self.investigation_id = investigation_id
        self.policy = policy
        self.start_time = time.monotonic()
        self.agent_timings: dict[str, dict] = {}
        self.token_usage: int = 0
        self.breaches: list[str] = []

    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.start_time

    def record_agent_start(self, agent_name: str) -> float:
        """Call at the start of each agent. Returns start timestamp."""
        start = time.monotonic()
        self.agent_timings[agent_name] = {
            "start": start,
            "end": None,
            "actual_seconds": None,
            "budget_seconds": self.policy.agent_timeouts.get(
                agent_name, 30
            ),
            "met": None,
        }
        return start

    def record_agent_end(self, agent_name: str) -> dict:
        """Call at the end of each agent. Returns timing result."""
        if agent_name not in self.agent_timings:
            return {}

        end = time.monotonic()
        entry = self.agent_timings[agent_name]
        entry["end"] = end
        entry["actual_seconds"] = round(end - entry["start"], 2)
        entry["met"] = (
            entry["actual_seconds"] <= entry["budget_seconds"]
        )

        if not entry["met"]:
            breach_msg = (
                f"AGENT_TIMEOUT: {agent_name} took "
                f"{entry['actual_seconds']}s "
                f"(budget: {entry['budget_seconds']}s)"
            )
            self.breaches.append(breach_msg)
            logger.warning(
                "[SLO] %s | %s",
                self.investigation_id,
                breach_msg,
            )

        return entry

    def add_tokens(self, token_count: int) -> None:
        """Accumulate token usage during reconstruction."""
        self.token_usage += token_count

    def check_time_budget(self) -> bool:
        """
        Returns True if within time budget.
        Call before starting a new ReAct iteration.
        """
        elapsed = self.elapsed_seconds()
        # Use 100s as the enforcement threshold (not 120s)
        # to leave buffer for synthesis and report agents
        within_budget = elapsed < 100
        if not within_budget:
            breach_msg = (
                f"TIME_BUDGET: {round(elapsed, 1)}s elapsed "
                f"(budget: {self.policy.investigation_time_budget_seconds}s)"
            )
            if breach_msg not in self.breaches:
                self.breaches.append(breach_msg)
                logger.warning(
                    "[SLO] %s | %s",
                    self.investigation_id,
                    breach_msg,
                )
        return within_budget

    def check_token_budget(self) -> bool:
        """
        Returns True if within token budget.
        Call before starting a new ReAct iteration.
        """
        within_budget = (
            self.token_usage < self.policy.reconstruction_token_budget
        )
        if not within_budget:
            breach_msg = (
                f"TOKEN_BUDGET: {self.token_usage} tokens used "
                f"(budget: {self.policy.reconstruction_token_budget})"
            )
            if breach_msg not in self.breaches:
                self.breaches.append(breach_msg)
                logger.warning(
                    "[SLO] %s | %s",
                    self.investigation_id,
                    breach_msg,
                )
        return within_budget

    def check_confidence_floor(self, confidence: float) -> bool:
        """
        Returns True if confidence meets the floor.
        Call after reconstruction completes.
        """
        meets_floor = confidence >= self.policy.confidence_floor
        if not meets_floor:
            breach_msg = (
                f"CONFIDENCE_FLOOR: {round(confidence, 3)} confidence "
                f"(floor: {self.policy.confidence_floor})"
            )
            if breach_msg not in self.breaches:
                self.breaches.append(breach_msg)
                logger.warning(
                    "[SLO] %s | %s",
                    self.investigation_id,
                    breach_msg,
                )
        return meets_floor

    def should_terminate_react(self) -> bool:
        """
        Called before each ReAct iteration.
        Returns True if the loop should stop due to SLO constraints.
        Checks both time and token budgets.
        """
        time_ok = self.check_time_budget()
        token_ok = self.check_token_budget()

        if not time_ok:
            logger.info(
                "[SLO] %s | Terminating ReAct — time budget approaching",
                self.investigation_id,
            )
        if not token_ok:
            logger.info(
                "[SLO] %s | Terminating ReAct — token budget reached",
                self.investigation_id,
            )

        return not (time_ok and token_ok)

    def generate_report(self, final_confidence: float) -> dict:
        """
        Generate the final SLO compliance report.
        Called at the end of the investigation pipeline.
        """
        elapsed = self.elapsed_seconds()
        self.check_confidence_floor(final_confidence)

        time_met = elapsed <= self.policy.investigation_time_budget_seconds
        token_met = (
            self.token_usage <= self.policy.reconstruction_token_budget
        )
        confidence_met = (
            final_confidence >= self.policy.confidence_floor
        )

        # Per-agent compliance summary
        agent_compliance = {}
        for name, timing in self.agent_timings.items():
            if timing.get("actual_seconds") is not None:
                agent_compliance[name] = {
                    "budget_seconds": timing["budget_seconds"],
                    "actual_seconds": timing["actual_seconds"],
                    "met": timing["met"],
                }

        all_agents_met = all(
            v["met"] for v in agent_compliance.values()
            if v["met"] is not None
        )

        overall_met = (
            time_met and token_met and confidence_met and all_agents_met
        )

        report = {
            "investigation_id": self.investigation_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "slo_1_time": {
                "budget_seconds": (
                    self.policy.investigation_time_budget_seconds
                ),
                "actual_seconds": round(elapsed, 2),
                "met": time_met,
            },
            "slo_2_tokens": {
                "budget_tokens": self.policy.reconstruction_token_budget,
                "actual_tokens": self.token_usage,
                "met": token_met,
            },
            "slo_3_confidence": {
                "floor": self.policy.confidence_floor,
                "actual": round(final_confidence, 3),
                "met": confidence_met,
            },
            "slo_4_agent_timeouts": agent_compliance,
            "overall_slo_status": "ALL_MET" if overall_met else "BREACHED",
            "slo_breaches": self.breaches,
            "breaches_count": len(self.breaches),
        }

        status = "✅ ALL_MET" if overall_met else f"⚠️ {len(self.breaches)} BREACH(ES)"
        logger.info(
            "[SLO] %s | Final report | status=%s | "
            "time=%.1fs | tokens=%d | confidence=%.2f",
            self.investigation_id,
            status,
            elapsed,
            self.token_usage,
            final_confidence,
        )

        return report


# ── Per-Investigation Monitor Registry ───────────────────────────────────────

_monitors: dict[str, SLOMonitor] = {}


def get_monitor(investigation_id: str) -> SLOMonitor:
    """
    Get or create an SLO monitor for an investigation.
    Creates a new monitor if one doesn't exist.
    """
    if investigation_id not in _monitors:
        _monitors[investigation_id] = SLOMonitor(investigation_id)
        logger.info(
            "[SLO] Monitor created | investigation_id=%s",
            investigation_id,
        )
    return _monitors[investigation_id]


def cleanup_monitor(investigation_id: str) -> None:
    """Remove monitor after investigation completes."""
    _monitors.pop(investigation_id, None)
