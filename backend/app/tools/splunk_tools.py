"""
splunk_tools.py
---------------
Async-friendly Splunk client for Splunk Sentinel.

splunklib is a synchronous SDK, so every blocking call is offloaded to a
ThreadPoolExecutor so the asyncio event loop is never blocked.

The 3-layer SPL safety check (spl_guardrail.check) is called before every
search — an unsafe query raises ValueError and is never sent to Splunk.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import splunklib.client as splunk_client
import splunklib.results as splunk_results

from app.config import settings
from app.guardrails import spl_guardrail

logger = logging.getLogger(__name__)

_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="splunk-worker")

AUDIT_LOG_PATH = Path("logs") / "spl_audit.log"

# Singleton instance — use get_splunk_client() to access
_splunk_client_instance: SplunkClient | None = None


def get_splunk_client() -> SplunkClient:
    """
    Singleton provider for the SplunkClient.
    Ensures the service connection is only established once per lifecycle.
    """
    global _splunk_client_instance
    if _splunk_client_instance is None:
        _splunk_client_instance = SplunkClient()
    return _splunk_client_instance


class SplunkClient:
    """
    Async wrapper around the synchronous splunklib SDK.

    All public methods are coroutines; blocking splunklib calls are
    dispatched to a shared ThreadPoolExecutor so that FastAPI / asyncio
    keep working while Splunk processes the query.
    """

    def __init__(self) -> None:
        """
        Connect to Splunk Enterprise using credentials from ``settings``.

        Raises:
            splunklib.binding.HTTPError: if credentials are wrong or Splunk
                                         is unreachable.
        """
        logger.info(
            "Connecting to Splunk at %s:%d as '%s' …",
            settings.SPLUNK_HOST,
            settings.SPLUNK_PORT,
            settings.SPLUNK_USERNAME,
        )
        self.service = splunk_client.connect(
            host=settings.SPLUNK_HOST,
            port=settings.SPLUNK_PORT,
            username=settings.SPLUNK_USERNAME,
            password=settings.SPLUNK_PASSWORD,
        )
        self.audit_log: list[str] = []
        logger.info(
            "Splunk connection established. Version: %s",
            self.service.info.get("version", "unknown"),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_spl_safety(self, spl: str) -> None:
        """
        Run the 3-layer SPL guardrail (delegated to spl_guardrail module).

        Layer 1 — Deterministic keyword block (zero LLM calls)
        Layer 2 — Index protection (only botsv3 permitted)
        Layer 3 — Audit logging (timestamps query in logs/spl_audit.log)

        Raises:
            ValueError: with a prefixed, human-readable message if any layer
                        blocks the query.
        """
        # Delegate to standalone module (raises ValueError on block)
        spl_guardrail.check(spl)

    def _run_oneshot(
        self,
        spl: str,
        earliest: str,
        latest: str,
        max_results: int,
    ) -> list[dict]:
        """
        Execute a synchronous Splunk oneshot search and return results as a
        list of plain Python dicts.

        This method is intended to be called inside a ThreadPoolExecutor — it
        blocks until Splunk finishes processing the search.

        Args:
            spl:         The SPL query string (already safety-checked).
            earliest:    Splunk ``earliest_time`` value.
            latest:      Splunk ``latest_time`` value.
            max_results: Maximum number of result rows to return.

        Returns:
            List of dicts, one per result row.
        """
        kwargs = {
            "earliest_time": earliest,
            "latest_time": latest,
            "count": max_results,
            "output_mode": "json",
        }
        raw = self.service.jobs.oneshot(spl, **kwargs)
        reader = splunk_results.JSONResultsReader(raw)
        rows: list[dict] = []
        for item in reader:
            if isinstance(item, splunk_results.Message):
                logger.debug("Splunk message: [%s] %s", item.type, item.message)
                continue
            if isinstance(item, dict):
                rows.append(item)
                if len(rows) >= max_results:
                    break
        return rows

    # ------------------------------------------------------------------
    # Public async interface
    # ------------------------------------------------------------------

    async def run_search(
        self,
        spl: str,
        earliest: str = "0",
        latest: str = "now",
        max_results: int = 500,
    ) -> list[dict]:
        """
        Run a Splunk oneshot search asynchronously and return results.

        The SPL is safety-checked via ``_check_spl_safety`` before being
        sent to Splunk.  The blocking splunklib call runs in the shared
        ThreadPoolExecutor so the asyncio event loop is not blocked.

        Args:
            spl:         SPL query to execute.
            earliest:    Splunk earliest time specifier (default ``"0"`` = all time).
            latest:      Splunk latest time specifier (default ``"now"``).
            max_results: Cap on the number of rows returned (default 500).

        Returns:
            List of result dicts (up to ``max_results`` entries).

        Raises:
            ValueError:  If the SPL is blocked by the guardrail.
            RuntimeError: If the Splunk search itself fails.
        """
        self._check_spl_safety(spl)

        # splunklib requires SPL to begin with 'search' keyword
        # when using the oneshot API
        normalized_spl = spl.strip()
        if not normalized_spl.lower().startswith("search "):
            normalized_spl = f"search {normalized_spl}"

        loop = asyncio.get_event_loop()
        try:
            results = await loop.run_in_executor(
                _EXECUTOR,
                self._run_oneshot,
                normalized_spl,
                earliest,
                latest,
                max_results,
            )
        except Exception as exc:
            logger.error("Splunk search failed | spl=%r | error=%s", spl[:120], exc)
            raise RuntimeError(f"Splunk search failed: {exc}") from exc

        logger.info(
            "Splunk search returned %d rows | spl=%r",
            len(results),
            spl[:80],
        )
        return results

    async def get_attack_window(self) -> dict:
        """Get the time range and peak activity window from botsv3."""
        spl = (
            "index=botsv3 earliest=0 "
            "| bucket _time span=1h "
            "| stats count by _time "
            "| sort _time "
            "| eval hour=strftime(_time, \"%Y-%m-%d %H:00\") "
            "| table hour, count "
            "| head 1000"
        )
        try:
            results = await self.run_search(spl)
            if not results:
                return {
                    "start": "unknown", "end": "unknown",
                    "peak_hour": "unknown", "peak_count": 0,
                    "total_events": 0
                }
            hours = [r["hour"] for r in results if "hour" in r]
            counts = [int(r.get("count", 0)) for r in results]
            total = sum(counts)
            peak_idx = counts.index(max(counts)) if counts else 0
            return {
                "start": hours[0] if hours else "unknown",
                "end": hours[-1] if hours else "unknown",
                "peak_hour": hours[peak_idx] if hours else "unknown",
                "peak_count": max(counts) if counts else 0,
                "total_events": total
            }
        except Exception as e:
            logger.error(f"get_attack_window failed: {e}")
            return {
                "start": "unknown", "end": "unknown",
                "peak_hour": "unknown", "peak_count": 0,
                "total_events": 0
            }

    async def get_top_source_ips(self, top_n: int = 10) -> list[dict]:
        """Get top source IPs by event count across all sourcetypes."""
        spl = (
            "index=botsv3 earliest=0 "
            "| stats count as event_count by src_ip "
            "| where isnotnull(src_ip) AND src_ip != \"\" "
            "| sort -event_count "
            f"| head {top_n}"
        )
        try:
            results = await self.run_search(spl)
            return [
                {
                    "ip": r.get("src_ip", "unknown"),
                    "event_count": int(r.get("event_count", 0))
                }
                for r in results
                if r.get("src_ip")
            ]
        except Exception as e:
            logger.error(f"get_top_source_ips failed: {e}")
            return []

