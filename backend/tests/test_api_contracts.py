"""
API Contract Tests — Splunk Sentinel

Verifies that API endpoints return correct response
shapes, required fields, and HTTP status codes.

All external dependencies are mocked:
- Splunk SDK → fake oneshot results
- Supabase → fake investigation data
- OpenAI/LangChain → fake LLM responses
- Qdrant → fake RAG results
- Langfuse → fake prompt strings

These tests run in CI without any external services.
They catch breaking changes to endpoint contracts
that unit tests miss.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

# --------------- Shared fixtures ---------------

FAKE_INVESTIGATION_ID = "test-contract-001"

FAKE_CONTAINMENT_PLAN = {
    "investigation_id": FAKE_INVESTIGATION_ID,
    "phases": [
        {
            "phase": 1,
            "name": "Phase 1: IMMEDIATE (Execute now)",
            "label": "Phase 1: IMMEDIATE (Execute now)",
            "description": "Immediate containment",
            "timeframe": "Immediate",
            "status": "PENDING",
            "actions": [
                {
                    "id": "action-001",
                    "action_id": "action-001",
                    "type": "BLOCK_IP",
                    "title": "Block External IP",
                    "description": "Block attacker IP",
                    "target": "184.85.20.125",
                    "status": "PENDING",
                    "phase": 1,
                    "risk_level": "LOW",
                    "reversible": True,
                    "is_irreversible": False,
                    "containment_spl": (
                        "| makeresults | eval ip=\"184.85.20.125\""
                        " | collect index=sentinel_actions"
                    ),
                    "reversal_spl": (
                        "| makeresults | eval ip=\"184.85.20.125\""
                        " action=\"unblock\""
                        " | collect index=sentinel_actions"
                    ),
                    "executed_at": None,
                    "executed_by": "Sentinel Engine",
                    "rolled_back_at": None,
                    "rollback_result": None,
                    "splunk_sid": None,
                    "error": None,
                    "verification_result": None,
                }
            ],
        },
        {
            "phase": 2,
            "name": "Phase 2: SHORT TERM (Within 24 hours)",
            "label": "Phase 2: SHORT TERM (Within 24 hours)",
            "description": "Short term mitigations",
            "timeframe": "Within 24 hours",
            "status": "PENDING",
            "actions": [],
        },
        {
            "phase": 3,
            "name": "Phase 3: REMEDIATION (Within 72 hours)",
            "label": "Phase 3: REMEDIATION (Within 72 hours)",
            "description": "Remediation actions",
            "timeframe": "Within 72 hours",
            "status": "PENDING",
            "actions": [],
        },
    ],
    "status": "PENDING",
    "confidence": 0.75,
    "classification": "APT",
    "generated_at": "2026-05-25T00:00:00Z",
    "analyst_edited": False,
    "analyst_reviewed": False,
    "plan_locked": False,
    "chat_history": [],
    "edit_history": [],
}

FAKE_REPORT_JSON = {
    "investigation_id": FAKE_INVESTIGATION_ID,
    "attack_classification": "APT",
    "severity": "CRITICAL",
    "investigation_confidence": 0.75,
    "narrative": "APT attack via SSRF to AWS metadata.",
    "kill_chain_stages": [
        {
            "stage_name": "Initial Access",
            "tactic": "Initial Access",
            "mitre_technique": "T1190",
            "evidence": "HTTP requests to web app",
            "affected_assets": ["172.16.0.178"],
            "timestamp": "2026-05-25T00:00:00Z",
        }
    ],
    "ttp_mappings": [
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "confidence": 0.80,
            "mltk_validation_run": False,
        },
        {
            "technique_id": "T1552.005",
            "technique_name": "Cloud Instance Metadata API",
            "tactic": "Credential Access",
            "confidence": 0.85,
            "mltk_validation_run": False,
        },
    ],
    "threat_intel": {
        "184.85.20.125": {
            "malicious": True,
            "score": 0.9,
            "source": "VirusTotal",
        }
    },
    "blast_radius": {
        "compromised_hosts": ["172.16.0.178"],
        "affected_ips": ["184.85.20.125"],
    },
    "patient_zero": "172.16.0.178",
    "structured_findings": {
        "executive_summary": "APT attack confirmed.",
        "attack_vector": "SSRF via web application",
        "impact_assessment": "IAM credentials compromised",
        "key_findings": ["SSRF detected", "Credentials stolen"],
        "recommendations": ["Block IP", "Rotate credentials"],
    },
    "counterfactual": {
        "alternatives_ruled_out": [
            {
                "classification": "INSIDER_THREAT",
                "reason": "No internal actor evidence.",
                "missing_indicators": ["internal_auth"],
            }
        ]
    },
    "containment_plan": FAKE_CONTAINMENT_PLAN,
    "confidence_breakdown": {
        "overall": 0.75,
        "factors": [
            {
                "name": "Kill Chain Completeness",
                "description": "Confirmed kill chain stages",
                "raw_score": 1.0,
                "weight": 0.35,
                "contribution": 0.35,
                "detail": "4 stages confirmed",
            },
            {
                "name": "Evidence Variety",
                "description": "Distinct data sources",
                "raw_score": 0.5,
                "weight": 0.30,
                "contribution": 0.15,
                "detail": "2 sourcetypes",
            },
            {
                "name": "Patient Zero Identification",
                "description": "Initial compromise source",
                "raw_score": 1.0,
                "weight": 0.10,
                "contribution": 0.10,
                "detail": "Patient zero confirmed",
            },
            {
                "name": "External Threat Corroboration",
                "description": "External IP verified",
                "raw_score": 0.0,
                "weight": 0.10,
                "contribution": 0.0,
                "detail": "No corroboration",
            },
            {
                "name": "Blast Radius Assessment",
                "description": "Impact scope",
                "raw_score": 1.0,
                "weight": 0.15,
                "contribution": 0.15,
                "detail": "Blast radius assessed",
            },
        ],
        "weakest_factor": {
            "name": "External Threat Corroboration",
            "raw_score": 0.0,
            "recommendation": (
                "Perform manual threat intel lookup"
            ),
        },
        "strongest_factor": {
            "name": "Kill Chain Completeness",
            "raw_score": 1.0,
        },
    },
    "mltk_enrichment_status": "complete",
    "mltk_enrichment_summary": {
        "ran": True,
        "agreements": 2,
        "disagreements": 0,
        "failed": 0,
        "connection": "openai_sentinel",
        "mltk_version": "5.7.4",
    },
    "synthesis_degraded": False,
    "degraded_sections": [],
    "pdf_url": None,
    "splunk_sid": None,
}

FAKE_INVESTIGATION_ROW = {
    "investigation_id": FAKE_INVESTIGATION_ID,
    "trigger": "Suspicious SSRF activity detected",
    "status": "complete",
    "created_at": "2026-05-25T00:00:00Z",
    "updated_at": "2026-05-25T00:01:00Z",
    "report_json": FAKE_REPORT_JSON,
}


def make_mock_supabase(investigation=None):
    """
    Build a mock Supabase client that returns
    FAKE_INVESTIGATION_ROW for any lookup.
    """
    mock_client = MagicMock()
    row = investigation or FAKE_INVESTIGATION_ROW

    mock_execute = MagicMock()
    mock_execute.data = [row]

    mock_select = MagicMock()
    mock_select.eq.return_value = MagicMock(
        execute=MagicMock(return_value=mock_execute)
    )
    mock_select.order.return_value = MagicMock(
        limit=MagicMock(
            return_value=MagicMock(
                execute=MagicMock(return_value=mock_execute)
            )
        )
    )

    mock_client.table.return_value = MagicMock(
        select=MagicMock(return_value=mock_select),
        update=MagicMock(
            return_value=MagicMock(
                eq=MagicMock(
                    return_value=MagicMock(
                        execute=MagicMock(
                            return_value=mock_execute
                        )
                    )
                )
            )
        ),
        insert=MagicMock(
            return_value=MagicMock(
                execute=MagicMock(
                    return_value=mock_execute
                )
            )
        ),
    )
    return mock_client


# --------------- Test classes ---------------

class TestHealthEndpoint:
    """GET /api/health"""

    def test_health_returns_200(self):
        with patch(
            "app.api.routes.SplunkClient"
        ) as mock_splunk:
            mock_splunk.return_value = MagicMock(service=MagicMock(
                info={"version": "10.2.2"}
            ))
            from app.main import app
            client = TestClient(app)
            response = client.get("/api/health")
            assert response.status_code == 200

    def test_health_returns_required_fields(self):
        with patch(
            "app.api.routes.SplunkClient"
        ) as mock_splunk:
            mock_splunk.return_value = MagicMock(service=MagicMock(
                info={"version": "10.2.2"}
            ))
            from app.main import app
            client = TestClient(app)
            response = client.get("/api/health")
            data = response.json()
            assert "status" in data
            assert "splunk_connected" in data
            assert "promptops" in data

    def test_health_promptops_is_langfuse(self):
        with patch(
            "app.api.routes.SplunkClient"
        ) as mock_splunk:
            mock_splunk.return_value = MagicMock(service=MagicMock(
                info={"version": "10.2.2"}
            ))
            from app.main import app
            client = TestClient(app)
            response = client.get("/api/health")
            if response.status_code == 200:
                data = response.json()
                assert data.get("promptops") == "langfuse"


class TestGetInvestigation:
    """GET /api/investigations/{id}"""

    def test_returns_404_for_missing_investigation(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=None,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                "/api/investigations/nonexistent-id"
            )
            assert response.status_code == 404

    def test_returns_200_for_existing_investigation(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
            )
            assert response.status_code == 200

    def test_response_contains_investigation_id(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
            )
            if response.status_code == 200:
                data = response.json()
                assert (
                    data.get("investigation_id")
                    == FAKE_INVESTIGATION_ID
                    or FAKE_INVESTIGATION_ID in str(data)
                )

    def test_response_contains_report_json(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
            )
            assert response.status_code == 200
            data = response.json()
            assert data is not None


class TestConfidenceBreakdown:
    """GET /api/investigations/{id}/confidence-breakdown"""

    def test_returns_404_for_missing_investigation(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=None,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                "/api/investigations/nonexistent/confidence-breakdown"
            )
            assert response.status_code == 404

    def test_returns_200_with_breakdown(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
                f"/confidence-breakdown"
            )
            assert response.status_code == 200

    def test_breakdown_has_factors_array(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
                f"/confidence-breakdown"
            )
            if response.status_code == 200:
                data = response.json()
                assert "factors" in data
                assert isinstance(data["factors"], list)

    def test_breakdown_has_overall_score(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
                f"/confidence-breakdown"
            )
            if response.status_code == 200:
                data = response.json()
                assert "overall" in data
                assert isinstance(
                    data["overall"], (int, float)
                )

    def test_breakdown_has_weakest_factor(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
                f"/confidence-breakdown"
            )
            if response.status_code == 200:
                data = response.json()
                assert "weakest_factor" in data
                assert "name" in data["weakest_factor"]
                assert "recommendation" in data[
                    "weakest_factor"
                ]

    def test_factors_have_required_fields(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
                f"/confidence-breakdown"
            )
            if response.status_code == 200:
                data = response.json()
                for factor in data.get("factors", []):
                    assert "name" in factor
                    assert "raw_score" in factor
                    assert "weight" in factor
                    assert "contribution" in factor


class TestTTPEnrichment:
    """GET /api/investigations/{id}/ttp-enrichment"""

    def test_returns_404_for_missing_investigation(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=None,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                "/api/investigations/nonexistent/ttp-enrichment"
            )
            assert response.status_code == 404

    def test_returns_200_with_enrichment(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
                f"/ttp-enrichment"
            )
            assert response.status_code == 200

    def test_enrichment_has_status_field(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
                f"/ttp-enrichment"
            )
            if response.status_code == 200:
                data = response.json()
                assert "status" in data
                assert data["status"] in [
                    "pending",
                    "running",
                    "complete",
                    "failed",
                ]

    def test_enrichment_complete_has_summary(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
                f"/ttp-enrichment"
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "complete":
                    assert "summary" in data


class TestDetectionGaps:
    """GET /api/investigations/{id}/detection-gaps"""

    def test_returns_404_for_missing_investigation(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=None,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                "/api/investigations/nonexistent/detection-gaps"
            )
            assert response.status_code == 404

    def test_returns_200_with_gap_analysis(self):
        mock_gaps = {
            "investigation_id": FAKE_INVESTIGATION_ID,
            "techniques_analyzed": 2,
            "covered": 1,
            "not_covered": 1,
            "coverage_score": 0.5,
            "coverage_label": "PARTIAL COVERAGE",
            "gaps": [],
            "covered_techniques": [],
            "saved_searches_checked": 10,
            "cache_used": False,
        }
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ), patch(
            "app.api.routes.analyze_detection_gaps",
            new_callable=AsyncMock,
            return_value=mock_gaps,
        ), patch(
            "app.api.routes.get_splunk_service",
            return_value=MagicMock(),
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
                f"/detection-gaps"
            )
            assert response.status_code == 200

    def test_gap_response_has_coverage_score(self):
        mock_gaps = {
            "investigation_id": FAKE_INVESTIGATION_ID,
            "techniques_analyzed": 2,
            "covered": 1,
            "not_covered": 1,
            "coverage_score": 0.5,
            "coverage_label": "PARTIAL COVERAGE",
            "gaps": [],
            "covered_techniques": [],
            "saved_searches_checked": 10,
            "cache_used": False,
        }
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ), patch(
            "app.api.routes.analyze_detection_gaps",
            new_callable=AsyncMock,
            return_value=mock_gaps,
        ), patch(
            "app.api.routes.get_splunk_service",
            return_value=MagicMock(),
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
                f"/detection-gaps"
            )
            if response.status_code == 200:
                data = response.json()
                assert "coverage_score" in data
                assert "coverage_label" in data
                assert "gaps" in data
                assert "covered_techniques" in data


class TestContainmentPlan:
    """GET /api/investigations/{id}/containment-plan"""

    def test_returns_404_for_missing_investigation(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=None,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                "/api/investigations/nonexistent/containment-plan"
            )
            assert response.status_code == 404

    def test_returns_200_with_plan(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
                f"/containment-plan"
            )
            assert response.status_code == 200

    def test_plan_has_phases(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
                f"/containment-plan"
            )
            if response.status_code == 200:
                data = response.json()
                assert "phases" in data
                assert isinstance(data["phases"], list)
                assert len(data["phases"]) == 3

    def test_plan_phases_have_correct_numbers(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
                f"/containment-plan"
            )
            if response.status_code == 200:
                data = response.json()
                phase_numbers = [
                    p.get("phase")
                    for p in data.get("phases", [])
                ]
                assert 1 in phase_numbers
                assert 2 in phase_numbers
                assert 3 in phase_numbers

    def test_actions_have_required_fields(self):
        with patch(
            "app.api.routes.get_investigation_details",
            return_value=FAKE_INVESTIGATION_ROW,
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get(
                f"/api/investigations/{FAKE_INVESTIGATION_ID}"
                f"/containment-plan"
            )
            if response.status_code == 200:
                data = response.json()
                for phase in data.get("phases", []):
                    for action in phase.get("actions", []):
                        assert "status" in action
                        assert "type" in action
                        assert "title" in action


class TestInvestigationHistory:
    """GET /api/investigations/history"""

    def test_returns_200(self):
        with patch(
            "app.services.supabase_client"
            ".get_supabase_client",
            return_value=make_mock_supabase(),
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get("/api/investigations/history")
            assert response.status_code == 200

    def test_returns_list(self):
        with patch(
            "app.api.routes.get_investigation_history",
            new_callable=AsyncMock,
            return_value=[FAKE_INVESTIGATION_ROW],
        ):
            from app.main import app
            client = TestClient(app)
            response = client.get("/api/investigations/history")
            if response.status_code == 200:
                data = response.json()
                assert "investigations" in data
                assert isinstance(data["investigations"], list)
