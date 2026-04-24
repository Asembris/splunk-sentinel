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
        Layer 3 — Audit logging (timestamps query in logs/spl_audit.log
                  AND appends to self.audit_log)

        Raises:
            ValueError: with a prefixed, human-readable message if any layer
                        blocks the query.
        """
        # Delegate to standalone module (raises ValueError on block)
        spl_guardrail.check(spl)

        # Also append to in-memory audit log for this investigation session
        timestamp = datetime.now(timezone.utc).isoformat()
        entry = f"[{timestamp}] {spl}"
        self.audit_log.append(entry)

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
        """
        Determine the temporal scope of the attack stored in botsv3.

        Runs an SPL that buckets events by hour, then identifies:
        - ``start``       — earliest hour with events
        - ``end``         — latest hour with events
        - ``peak_hour``   — the hour with the highest event count
        - ``peak_count``  — event count in the peak hour
        - ``total_events``— total events across the dataset

        Returns:
            Dict with keys: start, end, peak_hour, peak_count, total_events.
            Returns a safe default dict on failure (so the graph keeps running).
        """
        spl = (
            "index=botsv3 earliest=0"
            " | bucket _time span=1h"
            " | stats count by _time"
            " | sort _time"
            " | eval hour=strftime(_time, \"%Y-%m-%d %H:00\")"
            " | table hour, count"
        )
        try:
            rows = await self.run_search(spl, earliest="0", latest="now", max_results=10_000)
        except Exception as exc:
            logger.error("get_attack_window failed: %s", exc)
            return {
                "start": "unknown",
                "end": "unknown",
                "peak_hour": "unknown",
                "peak_count": 0,
                "total_events": 0,
            }

        if not rows:
            logger.warning("get_attack_window: no rows returned from Splunk.")
            return {
                "start": "unknown",
                "end": "unknown",
                "peak_hour": "unknown",
                "peak_count": 0,
                "total_events": 0,
            }

        hours: list[str] = []
        counts: list[int] = []
        for row in rows:
            hour = row.get("hour") or row.get("_time", "")
            try:
                count = int(row.get("count", 0))
            except (ValueError, TypeError):
                count = 0
            hours.append(str(hour))
            counts.append(count)

        total_events = sum(counts)
        peak_idx = counts.index(max(counts)) if counts else 0

        return {
            "start": hours[0] if hours else "unknown",
            "end": hours[-1] if hours else "unknown",
            "peak_hour": hours[peak_idx] if hours else "unknown",
            "peak_count": counts[peak_idx] if counts else 0,
            "total_events": total_events,
        }

    async def get_top_source_ips(self, top_n: int = 10) -> list[dict]:
        """
        Retrieve the top source IP addresses by event count from botsv3.

        Uses the ``src`` field which is the canonical Splunk CIM field for
        source address.  Falls back to ``src_ip`` if ``src`` is unavailable.

        Args:
            top_n: Number of top IPs to return (default 10).

        Returns:
            List of dicts with keys ``ip`` and ``event_count``,
            sorted descending by event_count.
            Returns an empty list on failure (graceful degradation).
        """
        spl = (
            f"index=botsv3 earliest=0"
            f" | stats count as event_count by src_ip"
            f" | where isnotnull(src_ip)"
            f" | sort -event_count"
            f" | head {top_n}"
            f" | rename src_ip as ip"
        )
        try:
            rows = await self.run_search(spl, earliest="0", latest="now", max_results=top_n)
        except Exception as exc:
            logger.error("get_top_source_ips failed: %s", exc)
            return []

        results: list[dict] = []
        for row in rows:
            ip = row.get("ip") or row.get("src") or "unknown"
            try:
                count = int(row.get("event_count", 0))
            except (ValueError, TypeError):
                count = 0
            results.append({"ip": str(ip), "event_count": count})

        logger.info("get_top_source_ips: found %d IPs", len(results))
        return results

    async def write_notable_event(
        self,
        title: str,
        description: str,
        severity: str = "high",
    ) -> bool:
        """
        Write an investigation finding back to Splunk as a notable event.

        Creates a summary index entry that Splunk ES can surface as a
        notable event.  Falls back to a standard index write if summary
        indexing is unavailable.

        Args:
            title:       Short title for the notable event.
            description: Full description / evidence summary.
            severity:    Splunk severity label (informational/low/medium/high/critical).

        Returns:
            True if the write succeeded, False if it failed.
        """
        # Build the SPL that writes to the summary index
        safe_title = title.replace('"', "'")
        safe_desc = description.replace('"', "'")[:1000]  # cap length

        spl = (
            f'| makeresults'
            f' | eval title="{safe_title}"'
            f', description="{safe_desc}"'
            f', severity="{severity}"'
            f', source="splunk-sentinel"'
            f', sourcetype="notable"'
            f' | collect index=summary'
        )
        try:
            # notable event writes target `summary` not `botsv3`; bypass guardrail
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                _EXECUTOR,
                self._run_oneshot,
                spl,
                "0",
                "now",
                1,
            )
            logger.info("Notable event written to Splunk summary index: %s", title)
            return True
        except Exception as exc:
            logger.error(
                "write_notable_event failed | title=%r | error=%s", title, exc
            )
            return False
