import pytest
from unittest.mock import MagicMock, AsyncMock
from app.guardrails.spl_guardrail import SPLGuardrail
from app.tools.splunk_tools import SplunkClient
from app.models.state import AgentState

@pytest.fixture
def guardrail():
    return SPLGuardrail()

@pytest.fixture
def mock_splunk_client():
    client = MagicMock(spec=SplunkClient)
    client.audit_log = []
    client.run_search = AsyncMock(return_value=[])
    return client

@pytest.fixture
def base_state():
    return AgentState(
        investigation_id="test-fixture-001",
        trigger="Test trigger for fixtures",
        attack_classification="UNKNOWN",
        classification_confidence=0,
        escalate_to_human=False,
        error=None,
        spl_audit_log=[],
        triage_summary="",
        kill_chain=[],
        patient_zero={},
        blast_radius={},
        threat_intel={},
        ttp_mappings=[],
        confidence_scores={},
        final_report={},
        attack_window={},
        top_source_ips=[],
    )
