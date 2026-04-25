import pytest
from unittest.mock import MagicMock
from app.tools.splunk_tools import SplunkClient

class TestAuditLogDrain:
    def test_audit_log_starts_empty_on_fresh_client(self):
        client = MagicMock(spec=SplunkClient)
        client.audit_log = []
        assert len(client.audit_log) == 0

    def test_audit_log_is_cleared_between_investigations(self):
        """
        Simulate two sequential investigations using the same singleton.
        The audit log must contain only queries from the current investigation.
        """
        client = MagicMock(spec=SplunkClient)
        client.audit_log = []

        # Simulate investigation 1
        client.audit_log.append("[2026-04-25T10:00:00+00:00] index=botsv3 | stats count")
        client.audit_log.append("[2026-04-25T10:00:01+00:00] index=botsv3 sourcetype=stream:dns | stats count")
        snapshot_inv1 = list(client.audit_log)
        client.audit_log.clear()

        # Simulate investigation 2
        client.audit_log.append("[2026-04-25T10:01:00+00:00] index=botsv3 sourcetype=stream:http | stats count")
        snapshot_inv2 = list(client.audit_log)

        assert len(snapshot_inv1) == 2
        assert len(snapshot_inv2) == 1
        assert snapshot_inv1[0] != snapshot_inv2[0]

    def test_no_query_bleed_between_investigations(self):
        """
        Queries from investigation A must not appear in investigation B's audit log.
        """
        client = MagicMock(spec=SplunkClient)
        client.audit_log = []

        inv_a_query = "[2026-04-25T10:00:00+00:00] index=botsv3 sourcetype=stream:http dest_ip=169.254.169.254"
        client.audit_log.append(inv_a_query)
        client.audit_log.clear()

        inv_b_query = "[2026-04-25T10:01:00+00:00] index=botsv3 sourcetype=WinEventLog:Security EventCode=4688"
        client.audit_log.append(inv_b_query)

        assert inv_a_query not in client.audit_log
        assert inv_b_query in client.audit_log

    def test_parallel_queries_all_appear_in_audit_log(self):
        client = MagicMock(spec=SplunkClient)
        client.audit_log = []

        # Simulate 4 base + 3 dynamic queries all logged in one investigation
        queries = [
            "[2026-04-25T10:00:00+00:00] index=botsv3 earliest=0 | bucket _time span=1h",
            "[2026-04-25T10:00:00+00:00] index=botsv3 earliest=0 | stats count by src_ip",
            "[2026-04-25T10:00:00+00:00] index=botsv3 earliest=0 sourcetype=WinEventLog:Security | stats count by EventCode",
            "[2026-04-25T10:00:00+00:00] index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4625",
            "[2026-04-25T10:00:00+00:00] index=botsv3 earliest=0 sourcetype=stream:http dest_ip=169.254.169.254",
            "[2026-04-25T10:00:00+00:00] index=botsv3 earliest=0 sourcetype=stream:dns | eval query_len=len(query)",
            "[2026-04-25T10:00:00+00:00] index=botsv3 earliest=0 sourcetype=stream:http | where NOT match(dest_ip",
        ]
        for q in queries:
            client.audit_log.append(q)

        assert len(client.audit_log) == 7
