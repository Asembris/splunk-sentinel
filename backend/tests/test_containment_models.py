"""
Tests for containment plan Pydantic models.
All deterministic — no LLM, Splunk, or Supabase.
"""
import pytest
from pydantic import ValidationError
from datetime import datetime, timezone
from app.models.containment import (
    ContainmentStatus,
    ContainmentActionType,
    RiskLevel,
    ContainmentAction,
    ContainmentPhase,
    ContainmentPlan,
    ActionType,
    ActionStatus,
    PlanStatus,
)


def make_reversible_action(**kwargs) -> ContainmentAction:
    defaults = {
        "action_id": "test-action-001",
        "type": ActionType.BLOCK_IP,
        "description": "Block target IP at the network boundary",
        "target": "192.168.1.100",
        "containment_spl": '| makeresults | eval ip="192.168.1.100", action="block", type="network", severity="high", reason="Sentinel investigation findings" | collect index=sentinel_actions',
        "reversal_spl": '| makeresults | eval ip="192.168.1.100", action="unblock", type="network", reason="Sentinel analyst rollback" | collect index=sentinel_actions',
        "status": ActionStatus.PENDING,
        "risk_level": RiskLevel.LOW,
    }
    defaults.update(kwargs)
    return ContainmentAction(**defaults)


class TestContainmentActionModel:
    def test_valid_action_creation(self):
        action = make_reversible_action()
        assert action.action_id == "test-action-001"
        assert action.id == "test-action-001"
        assert action.type == ContainmentActionType.BLOCK_IP
        assert action.status == ContainmentStatus.PENDING
        assert action.is_irreversible is False
        assert action.reversible is True

    def test_compatibility_id_syncs_with_action_id(self):
        # Provide id, should sync action_id
        action = ContainmentAction(
            id="my-action-id",
            type=ContainmentActionType.ISOLATE_HOST,
            description="Isolate host",
            target="host-001",
            containment_spl="...",
        )
        assert action.action_id == "my-action-id"
        assert action.id == "my-action-id"

        # Provide action_id, should sync id
        action2 = ContainmentAction(
            action_id="my-action-id-2",
            type=ContainmentActionType.ISOLATE_HOST,
            description="Isolate host",
            target="host-001",
            containment_spl="...",
        )
        assert action2.id == "my-action-id-2"
        assert action2.action_id == "my-action-id-2"

    def test_compatibility_is_irreversible_syncs_with_reversible(self):
        # Provide reversible=False, should set is_irreversible=True
        action = make_reversible_action(reversible=False)
        assert action.is_irreversible is True
        assert action.reversible is False

        # Provide is_irreversible=True, should set reversible=False
        action2 = make_reversible_action(is_irreversible=True)
        assert action2.reversible is False
        assert action2.is_irreversible is True

    def test_invalid_action_type_raises_validation_error(self):
        with pytest.raises(ValidationError):
            ContainmentAction(
                action_id="test",
                type="INVALID_TYPE",  # not in enum
                description="test",
                target="test",
                containment_spl="...",
            )

    def test_invalid_status_raises_validation_error(self):
        with pytest.raises(ValidationError):
            make_reversible_action(status="IN_PROGRESS")  # not in status enum


class TestContainmentPhaseModel:
    def test_valid_phase_creation(self):
        action = make_reversible_action()
        phase = ContainmentPhase(
            name="Phase 1",
            description="Immediate blocks",
            actions=[action],
            status=ContainmentStatus.PENDING,
        )
        assert phase.name == "Phase 1"
        assert phase.label == "Phase 1"
        assert phase.description == "Immediate blocks"
        assert phase.timeframe == "Immediate blocks"
        assert len(phase.actions) == 1
        assert phase.status == ContainmentStatus.PENDING

    def test_compatibility_label_syncs_with_name(self):
        # Provide label, should sync name
        phase = ContainmentPhase(
            label="Label Name",
            timeframe="Timeframe Desc",
            actions=[make_reversible_action()],
        )
        assert phase.name == "Label Name"
        assert phase.label == "Label Name"

        # Provide name, should sync label
        phase2 = ContainmentPhase(
            name="Name Label",
            description="Desc Timeframe",
            actions=[make_reversible_action()],
        )
        assert phase2.label == "Name Label"
        assert phase2.name == "Name Label"

    def test_compatibility_timeframe_syncs_with_description(self):
        # Provide timeframe, should sync description
        phase = ContainmentPhase(
            label="Test",
            timeframe="10 mins",
            actions=[make_reversible_action()],
        )
        assert phase.description == "10 mins"
        assert phase.timeframe == "10 mins"

        # Provide description, should sync timeframe
        phase2 = ContainmentPhase(
            label="Test",
            description="1 hour",
            actions=[make_reversible_action()],
        )
        assert phase2.timeframe == "1 hour"
        assert phase2.description == "1 hour"


class TestContainmentPlanModel:
    def test_valid_plan_creation(self):
        action = make_reversible_action()
        phase = ContainmentPhase(name="Phase 1", actions=[action])
        plan = ContainmentPlan(
            investigation_id="inv-001",
            plan_id="inv-001",
            phases=[phase],
            status=ContainmentStatus.PENDING,
        )
        assert plan.investigation_id == "inv-001"
        assert plan.plan_id == "inv-001"
        assert len(plan.phases) == 1
        assert plan.status == ContainmentStatus.PENDING
        assert isinstance(plan.generated_at, datetime)
        assert isinstance(plan.updated_at, datetime)

    def test_compatibility_plan_id_syncs_with_investigation_id(self):
        phase = ContainmentPhase(name="Phase 1", actions=[])
        plan = ContainmentPlan(
            plan_id="my-plan-id",
            phases=[phase],
        )
        assert plan.investigation_id == "my-plan-id"
        assert plan.plan_id == "my-plan-id"

    def test_compatibility_last_modified_at_syncs_with_updated_at(self):
        phase = ContainmentPhase(name="Phase 1", actions=[])
        dt = datetime(2026, 5, 4, 12, 0, 0, tzinfo=timezone.utc)
        plan = ContainmentPlan(
            investigation_id="inv-001",
            phases=[phase],
            last_modified_at=dt,
        )
        assert plan.updated_at == dt
        assert plan.last_modified_at == dt

    def test_action_counters(self):
        # Create a plan with diverse action statuses
        a1 = make_reversible_action(action_id="a1", status=ContainmentStatus.EXECUTED)
        a2 = make_reversible_action(action_id="a2", status=ContainmentStatus.FAILED)
        a3 = make_reversible_action(action_id="a3", status=ContainmentStatus.SKIPPED)
        a4 = make_reversible_action(action_id="a4", status=ContainmentStatus.ROLLED_BACK)
        a5 = make_reversible_action(action_id="a5", status=ContainmentStatus.PENDING)

        p1 = ContainmentPhase(name="P1", actions=[a1, a2])
        p2 = ContainmentPhase(name="P2", actions=[a3, a4, a5])

        plan = ContainmentPlan(investigation_id="inv-counter-test", phases=[p1, p2])

        assert plan.total_actions == 5
        assert plan.executed_actions == 1
        assert plan.failed_actions == 1
        assert plan.skipped_actions == 1
        assert plan.rolled_back_actions == 1

    def test_update_status_executing(self):
        # If any phase is executing, plan is executing
        p1 = ContainmentPhase(name="P1", status=ContainmentStatus.EXECUTING, actions=[])
        p2 = ContainmentPhase(name="P2", status=ContainmentStatus.PENDING, actions=[])
        plan = ContainmentPlan(investigation_id="inv-1", phases=[p1, p2])
        plan.update_status()
        assert plan.status == ContainmentStatus.EXECUTING

    def test_update_status_executed_complete(self):
        # If all phases are executed or skipped, plan is executed
        p1 = ContainmentPhase(name="P1", status=ContainmentStatus.EXECUTED, actions=[])
        p2 = ContainmentPhase(name="P2", status=ContainmentStatus.SKIPPED, actions=[])
        plan = ContainmentPlan(investigation_id="inv-1", phases=[p1, p2])
        plan.update_status()
        assert plan.status == ContainmentStatus.EXECUTED

    def test_update_status_failed(self):
        # If any phase is failed (and none executing), plan is failed
        p1 = ContainmentPhase(name="P1", status=ContainmentStatus.FAILED, actions=[])
        p2 = ContainmentPhase(name="P2", status=ContainmentStatus.PENDING, actions=[])
        plan = ContainmentPlan(investigation_id="inv-1", phases=[p1, p2])
        plan.update_status()
        assert plan.status == ContainmentStatus.FAILED
