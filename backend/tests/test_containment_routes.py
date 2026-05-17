"""
API routes integration tests for the containment plan system.
Uses FastAPI TestClient to request the routes and mocks Supabase / Containment Engine.
"""
import pytest
import json
from unittest.mock import MagicMock, AsyncMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.models.containment import ContainmentStatus, ContainmentActionType

client = TestClient(app)


@pytest.fixture
def mock_plan():
    return {
        "phases": [
            {
                "name": "Phase 1: IMMEDIATE (Execute now)",
                "description": "Immediate blocks",
                "actions": [
                    {
                        "action_id": "act-test-111",
                        "type": "BLOCK_IP",
                        "title": "Block IP",
                        "description": "Block C2",
                        "target": "1.1.1.1",
                        "containment_spl": "...",
                        "reversal_spl": "...",
                        "status": "PENDING",
                        "is_irreversible": False,
                    }
                ]
            }
        ]
    }


class TestGetContainmentPlanRoute:
    @patch("app.api.routes.get_investigation_details", new_callable=AsyncMock)
    def test_get_plan_success(self, mock_get_details, mock_plan):
        mock_get_details.return_value = {
            "classification": "APT",
            "severity": "CRITICAL",
            "report_json": {
                "containment_plan": mock_plan
            }
        }

        response = client.get("/api/investigations/inv-123/containment-plan")
        assert response.status_code == 200
        assert response.json() == mock_plan

    @patch("app.api.routes.get_investigation_details", new_callable=AsyncMock)
    def test_get_plan_investigation_not_found(self, mock_get_details):
        mock_get_details.return_value = None
        response = client.get("/api/investigations/inv-nonexistent/containment-plan")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    @patch("app.api.routes.get_investigation_details", new_callable=AsyncMock)
    def test_get_plan_missing_plan_in_report(self, mock_get_details):
        mock_get_details.return_value = {
            "classification": "APT",
            "severity": "CRITICAL",
            "report_json": {}  # no containment_plan
        }
        response = client.get("/api/investigations/inv-123/containment-plan")
        assert response.status_code == 404
        assert "containment plan not found" in response.json()["detail"].lower()


class TestUpdateContainmentPlanRoute:
    @patch("app.api.routes.persist_investigation", new_callable=AsyncMock, create=True)
    @patch("app.api.routes.get_investigation_details", new_callable=AsyncMock)
    def test_update_plan_success(self, mock_get_details, mock_persist, mock_plan):
        mock_get_details.return_value = {
            "classification": "APT",
            "severity": "CRITICAL",
            "report_json": {}
        }
        mock_persist.return_value = True

        response = client.put(
            "/api/investigations/inv-123/containment-plan",
            json=mock_plan
        )
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
        mock_persist.assert_called_once()

    @patch("app.api.routes.get_investigation_details", new_callable=AsyncMock)
    def test_update_plan_investigation_not_found(self, mock_get_details, mock_plan):
        mock_get_details.return_value = None
        response = client.put(
            "/api/investigations/inv-nonexistent/containment-plan",
            json=mock_plan
        )
        assert response.status_code == 404


class TestExecuteContainmentPhaseRoute:
    @patch("app.api.routes.execute_phase_stream")
    def test_execute_phase_sse_stream(self, mock_stream):
        async def dummy_generator(inv_id, phase_idx):
            yield "data: " + json.dumps({"event": "phase_started"}) + "\n\n"
            yield "data: " + json.dumps({"event": "phase_complete", "status": "COMPLETE"}) + "\n\n"

        mock_stream.return_value = dummy_generator(None, None)

        response = client.post(
            "/api/investigations/inv-123/containment-plan/execute",
            json={"phase": 1}
        )
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        assert "phase_started" in response.text
        assert "phase_complete" in response.text

    def test_execute_phase_missing_parameters_raises_400(self):
        response = client.post(
            "/api/investigations/inv-123/containment-plan/execute",
            json={}
        )
        assert response.status_code == 400
        assert "missing phase" in response.json()["detail"].lower()


class TestRollbackContainmentActionRoute:
    @patch("app.api.routes.rollback_action", new_callable=AsyncMock)
    def test_rollback_action_success(self, mock_rollback):
        mock_rollback.return_value = {
            "status": "success",
            "action_id": "act-test-111",
            "message": "Action rolled back successfully"
        }

        response = client.post(
            "/api/investigations/inv-123/containment-plan/rollback",
            json={"action_id": "act-test-111"}
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"
        assert response.json()["action_id"] == "act-test-111"

    @patch("app.api.routes.rollback_action", new_callable=AsyncMock)
    def test_rollback_action_fails_returns_500(self, mock_rollback):
        mock_rollback.return_value = {
            "status": "error",
            "message": "Action is irreversible"
        }

        response = client.post(
            "/api/investigations/inv-123/containment-plan/rollback",
            json={"action_id": "act-test-111"}
        )
        assert response.status_code == 500
        assert "irreversible" in response.json()["detail"].lower()

    def test_rollback_action_missing_id_raises_400(self):
        response = client.post(
            "/api/investigations/inv-123/containment-plan/rollback",
            json={}
        )
        assert response.status_code == 400
        assert "missing action_id" in response.json()["detail"].lower()
