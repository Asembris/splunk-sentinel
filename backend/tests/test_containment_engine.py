"""
Tests for containment execution engine, rollback logic, and SSE streaming.
Uses patching to mock Supabase and Splunk APIs.
"""
import pytest
import asyncio
import json
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timezone
from app.models.containment import (
    ContainmentAction,
    ContainmentPhase,
    ContainmentPlan,
    ContainmentStatus,
    ContainmentActionType,
)
from app.services.containment_engine import (
    validate_containment_spl,
    execute_action,
    rollback_action,
    execute_phase_stream,
    execute_single_action,
    execute_rollback_action,
    stream_phase_execution,
)




@pytest.fixture
def sample_action():
    return ContainmentAction(
        id="act-test-111",
        action_id="act-test-111",
        type=ContainmentActionType.BLOCK_IP,
        title="Block test IP",
        description="Block 1.1.1.1",
        target="1.1.1.1",
        containment_spl='| makeresults | eval ip="1.1.1.1", action="block" | collect index=sentinel_actions',
        reversal_spl='| makeresults | eval ip="1.1.1.1", action="unblock" | collect index=sentinel_actions',
        status=ContainmentStatus.PENDING,
        is_irreversible=False,
    )


@pytest.fixture
def sample_plan(sample_action):
    phase = ContainmentPhase(
        name="Phase 1: IMMEDIATE (Execute now)",
        description="Immediate actions",
        actions=[sample_action],
        status=ContainmentStatus.PENDING,
    )
    return ContainmentPlan(
        investigation_id="inv-engine-test",
        phases=[phase],
        status=ContainmentStatus.PENDING,
    )


class TestValidateContainmentSplEngine:
    def test_accepts_valid_sentinel_actions_spl(self):
        spl = '| makeresults | eval ip="10.0.0.1" | collect index=sentinel_actions'
        assert validate_containment_spl(spl) is True

    def test_rejects_non_sentinel_actions_index(self):
        spl = '| makeresults | eval ip="10.0.0.1" | collect index=other_index'
        assert validate_containment_spl(spl) is False

    def test_rejects_unsafe_spl(self):
        # Contains blocked keyword like "delete" or "outputlookup" or similar depending on spl_guardrail
        # Let's test a known unsafe SPL that is blocked by the guardrail
        spl = '| inputlookup admin_users.csv | delete | collect index=sentinel_actions'
        assert validate_containment_spl(spl) is False


class TestExecuteAction:
    @pytest.mark.asyncio
    @patch("app.services.containment_engine.get_splunk_client")
    async def test_executes_pending_action_successfully(self, mock_get_splunk, sample_action):
        mock_splunk = MagicMock()
        mock_splunk.service.jobs.oneshot = MagicMock(return_value=[])
        mock_get_splunk.return_value = mock_splunk

        result = await execute_action(sample_action)
        assert result.status == ContainmentStatus.EXECUTED
        assert result.error is None
        assert isinstance(result.executed_at, datetime)
        mock_splunk.service.jobs.oneshot.assert_called_once_with(
            sample_action.containment_spl,
            earliest_time="0",
            latest_time="now",
            output_mode="json"
        )

    @pytest.mark.asyncio
    @patch("app.services.containment_engine.get_splunk_client")
    async def test_skips_already_executed_action(self, mock_get_splunk, sample_action):
        sample_action.status = ContainmentStatus.EXECUTED
        mock_splunk = MagicMock()
        mock_get_splunk.return_value = mock_splunk

        result = await execute_action(sample_action)
        assert result.status == ContainmentStatus.EXECUTED
        mock_splunk.service.jobs.oneshot.assert_not_called()

    @pytest.mark.asyncio
    @patch("app.services.containment_engine.get_splunk_client")
    async def test_fails_action_if_spl_invalid(self, mock_get_splunk, sample_action):
        # Change SPL to target other index to trigger validation failure
        sample_action.containment_spl = '| makeresults | collect index=some_other_index'
        mock_splunk = MagicMock()
        mock_get_splunk.return_value = mock_splunk

        result = await execute_action(sample_action)
        assert result.status == ContainmentStatus.FAILED
        assert "validation failed" in result.error
        mock_splunk.service.jobs.oneshot.assert_not_called()

    @pytest.mark.asyncio
    @patch("app.services.containment_engine.get_splunk_client")
    async def test_handles_splunk_oneshot_exception(self, mock_get_splunk, sample_action):
        mock_splunk = MagicMock()
        mock_splunk.service.jobs.oneshot = MagicMock(side_effect=Exception("Splunk connection reset"))
        mock_get_splunk.return_value = mock_splunk

        result = await execute_action(sample_action)
        assert result.status == ContainmentStatus.FAILED
        assert "Splunk connection reset" in result.error


class TestRollbackAction:
    @pytest.mark.asyncio
    @patch("app.services.containment_engine.patch_containment_plan", new_callable=AsyncMock)
    @patch("app.services.containment_engine.get_investigation_details", new_callable=AsyncMock)
    @patch("app.services.containment_engine.get_splunk_client")
    async def test_rolls_back_executed_action_successfully(
        self, mock_get_splunk, mock_get_details, mock_patch_plan, sample_action, sample_plan
    ):
        # Configure action as EXECUTED in the plan
        sample_action.status = ContainmentStatus.EXECUTED
        sample_plan.phases[0].actions[0] = sample_action

        # Mock Supabase fetch
        mock_get_details.return_value = {
            "classification": "APT",
            "severity": "CRITICAL",
            "report_json": {
                "containment_plan": sample_plan.model_dump(mode="json")
            }
        }

        # Mock Splunk
        mock_splunk = MagicMock()
        mock_splunk.service.jobs.oneshot = MagicMock(return_value=[])
        mock_get_splunk.return_value = mock_splunk

        # Mock Persist
        mock_patch_plan.return_value = True

        res = await rollback_action("inv-engine-test", "act-test-111")
        assert res["status"] == "success"
        assert res["action_id"] == "act-test-111"

        # Verify patch_containment_plan was called with the updated plan
        # New signature: patch_containment_plan(investigation_id, plan_dict)
        mock_patch_plan.assert_called_once()
        call_args = mock_patch_plan.call_args[0]
        assert call_args[0] == "inv-engine-test"           # investigation_id
        persisted_plan = call_args[1]                       # plan dict
        assert persisted_plan["phases"][0]["actions"][0]["status"] == ContainmentStatus.ROLLED_BACK

    @pytest.mark.asyncio
    @patch("app.services.containment_engine.get_investigation_details", new_callable=AsyncMock)
    async def test_rollback_returns_error_if_investigation_missing(self, mock_get_details):
        mock_get_details.return_value = None
        res = await rollback_action("non-existent-inv", "act-111")
        assert res["status"] == "error"
        assert "not found" in res["message"].lower()

    @pytest.mark.asyncio
    @patch("app.services.containment_engine.get_investigation_details", new_callable=AsyncMock)
    async def test_rollback_returns_error_if_action_irreversible(self, mock_get_details, sample_action, sample_plan):
        # Configure action as irreversible
        sample_action.status = ContainmentStatus.EXECUTED
        sample_action.reversal_spl = None
        sample_action.is_irreversible = True
        sample_plan.phases[0].actions[0] = sample_action

        mock_get_details.return_value = {
            "classification": "APT",
            "severity": "CRITICAL",
            "report_json": {
                "containment_plan": sample_plan.model_dump(mode="json")
            }
        }

        res = await rollback_action("inv-engine-test", "act-test-111")
        assert res["status"] == "error"
        assert "irreversible" in res["message"].lower()


class TestExecutePhaseStream:
    @pytest.mark.asyncio
    @patch("app.services.containment_engine.patch_containment_plan", new_callable=AsyncMock)
    @patch("app.services.containment_engine.get_investigation_details", new_callable=AsyncMock)
    @patch("app.services.containment_engine.get_splunk_client")
    async def test_streams_events_successfully(
        self, mock_get_splunk, mock_get_details, mock_patch_plan, sample_action, sample_plan
    ):
        mock_get_details.return_value = {
            "classification": "APT",
            "severity": "CRITICAL",
            "report_json": {
                "containment_plan": sample_plan.model_dump(mode="json")
            }
        }

        mock_splunk = MagicMock()
        mock_splunk.service.jobs.oneshot = MagicMock(return_value=[])
        mock_get_splunk.return_value = mock_splunk
        mock_patch_plan.return_value = True

        events = []
        async for sse_event in execute_phase_stream("inv-engine-test", 0):
            assert "data" in sse_event
            events.append(json.loads(sse_event["data"]))

        # Check standard SSE event sequence
        assert events[0]["event"] == "phase_started"
        assert events[1]["event"] == "action_started"
        assert events[2]["event"] == "action_complete"
        assert events[3]["event"] == "phase_complete"
        assert events[3]["status"] == ContainmentStatus.COMPLETE


class TestCompatibilityHelpers:
    @pytest.mark.asyncio
    async def test_execute_single_action_helper(self):
        mock_service = MagicMock()
        # Mock Oneshot returning a list with at least 1 element to simulate successful execute
        mock_service.jobs.oneshot = MagicMock(return_value=["row1"])

        action = ContainmentAction(
            id="act-compat-001",
            type=ContainmentActionType.BLOCK_IP,
            description="Block test",
            target="1.1.1.1",
            containment_spl='| makeresults | eval ip="1.1.1.1", action="block" | collect index=sentinel_actions',
        )

        res = await execute_single_action(action, mock_service, "inv-001")
        assert res["status"] == "EXECUTED"
        assert action.status == ContainmentStatus.EXECUTED

    @pytest.mark.asyncio
    async def test_execute_rollback_action_helper(self):
        mock_service = MagicMock()
        mock_service.jobs.oneshot = MagicMock(return_value=["row1"])

        action = ContainmentAction(
            id="act-compat-002",
            type=ContainmentActionType.BLOCK_IP,
            description="Block test",
            target="1.1.1.1",
            containment_spl='| makeresults | eval ip="1.1.1.1", action="block" | collect index=sentinel_actions',
            reversal_spl='| makeresults | eval ip="1.1.1.1", action="unblock" | collect index=sentinel_actions',
            status=ContainmentStatus.EXECUTED,
            is_irreversible=False,
        )

        res = await execute_rollback_action(action, "rollback reason", mock_service, "inv-001")
        assert res["status"] == "ROLLED_BACK"
        assert action.status == ContainmentStatus.ROLLED_BACK

    @pytest.mark.asyncio
    async def test_stream_phase_execution_helper(self, sample_plan):
        mock_service = MagicMock()
        mock_service.jobs.oneshot = MagicMock(return_value=["row1"])

        events = []
        async for sse_event in stream_phase_execution(sample_plan, 0, mock_service):
            assert "data" in sse_event
            events.append(json.loads(sse_event["data"]))

        assert events[0]["event"] == "phase_start"
        assert events[1]["event"] == "action_started"
        assert events[2]["event"] == "action_complete"
        assert events[3]["event"] == "phase_complete"
        assert events[3]["status"] == ContainmentStatus.COMPLETE
