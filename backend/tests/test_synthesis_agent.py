"""
Tests for synthesis agent, report generation, counterfactual reasoning,
and containment plan synthesis.
Uses patching to mock OpenAI ChatOpenAI and RAG retriever.
"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from pydantic import ValidationError
from datetime import datetime, timezone

from app.models.state import AgentState
from app.models.containment import ContainmentStatus, ContainmentActionType
from app.agents.synthesis_agent import (
    FindingWithConfidence,
    RecommendedAction,
    NarrativeSection,
    StructuredSection,
    FinalReportRaw,
    _get_alternative_classifications,
    _is_valid_kill_process_target,
    _generate_counterfactual_reasoning,
    _generate_containment_plan,
    _inject_missing_fields,
    synthesis_agent,
)


class TestSynthesisHelperFunctions:
    def test_alternative_classifications(self):
        assert set(_get_alternative_classifications("APT")) == {
            "RANSOMWARE", "INSIDER_THREAT", "BRUTE_FORCE"
        }
        assert set(_get_alternative_classifications("RANSOMWARE")) == {
            "APT", "INSIDER_THREAT", "BRUTE_FORCE"
        }

    def test_is_valid_kill_process_target(self):
        assert _is_valid_kill_process_target("powershell.exe") is True
        assert _is_valid_kill_process_target("cmd.exe") is True
        assert _is_valid_kill_process_target("suspicious_process") is False
        assert _is_valid_kill_process_target("placeholder") is False
        assert _is_valid_kill_process_target("any remaining suspicious process") is False


class TestInjectMissingFields:
    def test_injects_all_fields_when_empty(self):
        raw = FinalReportRaw()
        kill_chain = [
            {"stage_name": "Initial Access", "confidence": "CONFIRMED", "mitre_technique": "T1190"}
        ]
        threat_intel = {"1.1.1.1": {"score": 50}}
        ttp_mappings = [{"technique_id": "T1190"}]

        injected = _inject_missing_fields(
            raw, "APT", kill_chain, threat_intel, ttp_mappings, 0.8
        )

        assert "APT" in injected.executive_summary
        assert "Initial Access" in injected.attack_overview
        assert len(injected.key_findings) == 1
        assert injected.key_findings[0].confidence == 0.8
        assert len(injected.recommended_actions) == 1
        assert injected.recommended_actions[0].mitre_technique == "T1078"
        assert "T1190" in injected.mitre_techniques_used
        assert injected.investigation_confidence > 0.0
        assert "APT" in injected.threat_actor_profile

    def test_does_not_override_existing_fields(self):
        raw = FinalReportRaw(
            executive_summary="Custom executive summary",
            attack_overview="Custom attack overview",
            key_findings=[FindingWithConfidence(
                finding="Finding 1", evidence="Evidence 1", confidence=0.9, source="telemetry"
            )],
            recommended_actions=[RecommendedAction(
                priority="IMMEDIATE", action="Action 1", rationale="Rationale 1", mitre_technique="T1190"
            )],
            mitre_techniques_used=["T1190"],
            threat_actor_profile="Sophisticated attacker",
            investigation_confidence=0.85
        )

        injected = _inject_missing_fields(
            raw, "APT", [], {}, [], 0.5
        )

        assert injected.executive_summary == "Custom executive summary"
        assert injected.attack_overview == "Custom attack overview"
        assert len(injected.key_findings) == 1
        assert injected.key_findings[0].finding == "Finding 1"
        assert len(injected.recommended_actions) == 1
        assert injected.mitre_techniques_used == ["T1190"]
        assert injected.threat_actor_profile == "Sophisticated attacker"
        assert injected.investigation_confidence == 0.85


class TestGenerateCounterfactualReasoning:
    @pytest.mark.asyncio
    @patch("langchain_openai.ChatOpenAI")
    async def test_generates_reasoning_successfully(self, mock_llm_class):
        mock_llm = mock_llm_class.return_value
        # Mock LLM ainvoke output
        mock_response = MagicMock()
        mock_response.content = """
        {
          "alternatives_ruled_out": [
            {
              "classification": "RANSOMWARE",
              "reason": "No shadow copy deletions or encryption activity observed.",
              "missing_indicators": ["vssadmin.exe", "shadow copy delete"]
            }
          ]
        }
        """
        mock_llm.ainvoke = AsyncMock(return_value=mock_response)

        res = await _generate_counterfactual_reasoning(
            classification="APT",
            kill_chain=[],
            key_indicators=[],
            triage_summary="",
            attack_narrative="",
            llm=mock_llm
        )

        assert res["confirmed_classification"] == "APT"
        assert len(res["alternatives_ruled_out"]) == 1
        assert res["alternatives_ruled_out"][0]["classification"] == "RANSOMWARE"

    @pytest.mark.asyncio
    @patch("langchain_openai.ChatOpenAI")
    async def test_handles_json_codeblock_markers(self, mock_llm_class):
        mock_llm = mock_llm_class.return_value
        mock_response = MagicMock()
        mock_response.content = """```json
        {
          "alternatives_ruled_out": []
        }
        ```"""
        mock_llm.ainvoke = AsyncMock(return_value=mock_response)

        res = await _generate_counterfactual_reasoning(
            classification="APT",
            kill_chain=[],
            key_indicators=[],
            triage_summary="",
            attack_narrative="",
            llm=mock_llm
        )
        assert res["alternatives_ruled_out"] == []

    @pytest.mark.asyncio
    @patch("langchain_openai.ChatOpenAI")
    async def test_returns_error_info_on_llm_failure(self, mock_llm_class):
        mock_llm = mock_llm_class.return_value
        mock_llm.ainvoke = AsyncMock(side_effect=Exception("API limit exceeded"))

        res = await _generate_counterfactual_reasoning(
            classification="APT",
            kill_chain=[],
            key_indicators=[],
            triage_summary="",
            attack_narrative="",
            llm=mock_llm
        )
        assert "error" in res
        assert res["alternatives_ruled_out"] == []


class TestGenerateContainmentPlan:
    @pytest.mark.asyncio
    @patch("langchain_openai.ChatOpenAI")
    async def test_filters_invalid_targets_and_generates_valid_plan(self, mock_llm_class):
        mock_llm = mock_llm_class.return_value
        mock_response = MagicMock()
        mock_response.content = """
        {
          "phases": [
            {
              "name": "Phase 1: IMMEDIATE (Execute now)",
              "description": "Immediate blocks...",
              "actions": [
                {
                  "type": "BLOCK_IP",
                  "target": "104.244.42.1",
                  "title": "Block IP",
                  "description": "C2 server"
                },
                {
                  "type": "KILL_PROCESS",
                  "target": "suspicious_process_id",
                  "title": "Kill Process",
                  "description": "Bad process"
                },
                {
                  "type": "KILL_PROCESS",
                  "target": "cmd.exe",
                  "title": "Kill Cmd Shell",
                  "description": "Malicious execution shell"
                }
              ]
            }
          ]
        }
        """
        mock_llm.ainvoke = AsyncMock(return_value=mock_response)

        plan = await _generate_containment_plan(
            investigation_id="inv-synthesis-test",
            blast_radius={},
            kill_chain=[],
            classification="APT",
            llm=mock_llm
        )

        assert plan["investigation_id"] == "inv-synthesis-test"
        # Verify invalid kill_process action was skipped, valid one kept
        p1_actions = plan["phases"][0]["actions"]
        assert len(p1_actions) == 2

        # First action: BLOCK_IP
        assert p1_actions[0]["type"] == "BLOCK_IP"
        assert p1_actions[0]["target"] == "104.244.42.1"
        assert p1_actions[0]["is_irreversible"] is False

        # Second action: KILL_PROCESS (cmd.exe)
        assert p1_actions[1]["type"] == "KILL_PROCESS"
        assert p1_actions[1]["target"] == "cmd.exe"
        assert p1_actions[1]["is_irreversible"] is True


class TestSynthesisAgentMain:
    @pytest.mark.asyncio
    @patch("app.agents.synthesis_agent.retrieve_for_synthesis", new_callable=AsyncMock)
    @patch("app.agents.synthesis_agent._LLM")
    @patch("app.agents.synthesis_agent._LLM_NARRATIVE")
    @patch("app.agents.synthesis_agent._LLM_STRUCTURED")
    async def test_synthesis_agent_end_to_end(
        self, mock_llm_structured, mock_llm_narrative, mock_llm, mock_retrieve, base_state
    ):
        # Configure state
        base_state["investigation_id"] = "inv-synthesis-main"
        base_state["attack_classification"] = "APT"
        base_state["severity"] = "CRITICAL"
        base_state["reconstruction_confidence"] = 0.90
        base_state["patient_zero"] = {"ip_address": "10.0.0.5"}
        base_state["blast_radius"] = {"total_ips": 5}

        # Mock retrieve
        mock_retrieve.return_value = {
            "mitre": [{"id": "T1190", "name": "Exploitation"}],
            "cve": [],
            "playbooks": [],
            "botsv3": []
        }

        # Mock LLM Narrative
        mock_narrative_out = NarrativeSection(
            executive_summary="LLM Exec Summary",
            attack_overview="LLM Attack Overview",
            threat_actor_profile="LLM Threat Actor"
        )
        mock_llm_narrative.with_config.return_value.ainvoke = AsyncMock(return_value=mock_narrative_out)

        # Mock LLM Structured
        mock_structured_out = StructuredSection(
            key_findings=[
                FindingWithConfidence(finding=f"Finding {i}", evidence="Telemetry", confidence=0.8, source="telemetry")
                for i in range(4)
            ],
            recommended_actions=[
                RecommendedAction(priority="IMMEDIATE", action="Block", rationale="C2", mitre_technique="T1190")
            ],
            mitre_techniques_used=["T1190"],
            investigation_confidence=0.85
        )
        mock_llm_structured.with_config.return_value.ainvoke = AsyncMock(return_value=mock_structured_out)

        # Mock generic LLM responses for Containment Plan and Counterfactuals
        mock_containment_response = MagicMock()
        mock_containment_response.content = '{"phases": []}'
        mock_counterfactual_response = MagicMock()
        mock_counterfactual_response.content = '{"alternatives_ruled_out": []}'
        mock_llm.ainvoke = AsyncMock(side_effect=[mock_counterfactual_response, mock_containment_response])

        # Execute agent
        updated_state = await synthesis_agent(base_state)

        assert updated_state["error"] is None
        final_report = updated_state["final_report"]
        assert final_report["investigation_id"] == "inv-synthesis-main"
        assert final_report["classification"] == "APT"
        assert final_report["severity"] == "CRITICAL"
        assert final_report["executive_summary"] == "LLM Exec Summary"
        assert final_report["attack_overview"] == "LLM Attack Overview"
        assert len(final_report["key_findings"]) == 4
        assert len(final_report["recommended_actions"]) == 1
        assert "containment_plan" in final_report
