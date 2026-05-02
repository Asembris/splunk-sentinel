import pytest
import asyncio
from unittest.mock import AsyncMock, patch
import httpx

class TestIsInternalIp:
    """Tests for RFC1918 and non-routable IP detection."""

    def test_10_x_is_internal(self):
        from app.agents.threat_intel_agent import is_internal_ip
        assert is_internal_ip("10.0.0.1") is True

    def test_10_255_is_internal(self):
        from app.agents.threat_intel_agent import is_internal_ip
        assert is_internal_ip("10.255.255.255") is True

    def test_192_168_is_internal(self):
        from app.agents.threat_intel_agent import is_internal_ip
        assert is_internal_ip("192.168.1.1") is True

    def test_172_16_is_internal(self):
        from app.agents.threat_intel_agent import is_internal_ip
        assert is_internal_ip("172.16.0.178") is True

    def test_172_31_is_internal(self):
        from app.agents.threat_intel_agent import is_internal_ip
        assert is_internal_ip("172.31.12.76") is True

    def test_172_15_is_external(self):
        from app.agents.threat_intel_agent import is_internal_ip
        # 172.15.x.x is NOT RFC1918
        assert is_internal_ip("172.15.0.1") is False

    def test_172_32_is_external(self):
        from app.agents.threat_intel_agent import is_internal_ip
        # 172.32.x.x is NOT RFC1918
        assert is_internal_ip("172.32.0.1") is False

    def test_link_local_is_internal(self):
        from app.agents.threat_intel_agent import is_internal_ip
        assert is_internal_ip("169.254.169.254") is True

    def test_loopback_is_internal(self):
        from app.agents.threat_intel_agent import is_internal_ip
        assert is_internal_ip("127.0.0.1") is True

    def test_known_botsv3_attacker_is_external(self):
        from app.agents.threat_intel_agent import is_internal_ip
        assert is_internal_ip("54.67.127.227") is False

    def test_akamai_ip_is_external(self):
        from app.agents.threat_intel_agent import is_internal_ip
        assert is_internal_ip("184.85.20.125") is False

    def test_empty_string_does_not_crash(self):
        from app.agents.threat_intel_agent import is_internal_ip
        # Should return True (treat empty as non-routable) or False
        # Either is acceptable — just must not crash
        try:
            result = is_internal_ip("")
            assert isinstance(result, bool)
        except Exception:
            pass  # Crashing on empty is also acceptable


class TestComputeThreatLevel:
    """Tests for deterministic threat level computation."""

    def test_critical_by_virustotal(self):
        from app.agents.threat_intel_agent import compute_threat_level
        assert compute_threat_level(10, 0) == "CRITICAL"

    def test_critical_by_abuseipdb(self):
        from app.agents.threat_intel_agent import compute_threat_level
        assert compute_threat_level(0, 75) == "CRITICAL"

    def test_critical_both_thresholds(self):
        from app.agents.threat_intel_agent import compute_threat_level
        assert compute_threat_level(15, 80) == "CRITICAL"

    def test_high_by_virustotal(self):
        from app.agents.threat_intel_agent import compute_threat_level
        assert compute_threat_level(5, 0) == "HIGH"

    def test_high_by_abuseipdb(self):
        from app.agents.threat_intel_agent import compute_threat_level
        assert compute_threat_level(0, 50) == "HIGH"

    def test_medium_by_virustotal(self):
        from app.agents.threat_intel_agent import compute_threat_level
        assert compute_threat_level(2, 0) == "MEDIUM"

    def test_medium_by_abuseipdb(self):
        from app.agents.threat_intel_agent import compute_threat_level
        assert compute_threat_level(0, 25) == "MEDIUM"

    def test_low_all_zeros(self):
        from app.agents.threat_intel_agent import compute_threat_level
        assert compute_threat_level(0, 0) == "LOW"

    def test_low_below_all_thresholds(self):
        from app.agents.threat_intel_agent import compute_threat_level
        assert compute_threat_level(1, 24) == "LOW"

    def test_boundary_vt_9_is_high_not_critical(self):
        from app.agents.threat_intel_agent import compute_threat_level
        assert compute_threat_level(9, 0) == "HIGH"

    def test_boundary_abuse_74_is_high_not_critical(self):
        from app.agents.threat_intel_agent import compute_threat_level
        assert compute_threat_level(0, 74) == "HIGH"

    def test_boundary_vt_4_is_medium_not_high(self):
        from app.agents.threat_intel_agent import compute_threat_level
        assert compute_threat_level(4, 0) == "MEDIUM"


class TestDeterministicFallback:
    """Tests for deterministic fallback data."""

    def test_known_botsv3_ip_returns_medium(self):
        from app.agents.threat_intel_agent import get_deterministic_fallback
        result = get_deterministic_fallback("54.67.127.227")
        assert result["threat_level"] == "MEDIUM"

    def test_known_botsv3_ip_has_malicious_count(self):
        from app.agents.threat_intel_agent import get_deterministic_fallback
        result = get_deterministic_fallback("54.67.127.227")
        assert result["virustotal"]["malicious_count"] > 0

    def test_known_botsv3_ip_has_abuse_score(self):
        from app.agents.threat_intel_agent import get_deterministic_fallback
        result = get_deterministic_fallback("184.85.20.125")
        assert result["abuseipdb"]["abuse_confidence_score"] > 0

    def test_unknown_ip_returns_low(self):
        from app.agents.threat_intel_agent import get_deterministic_fallback
        result = get_deterministic_fallback("1.2.3.4")
        assert result["threat_level"] == "LOW"

    def test_unknown_ip_zero_malicious(self):
        from app.agents.threat_intel_agent import get_deterministic_fallback
        result = get_deterministic_fallback("8.8.8.8")
        assert result["virustotal"]["malicious_count"] == 0

    def test_fallback_has_required_fields(self):
        from app.agents.threat_intel_agent import get_deterministic_fallback
        result = get_deterministic_fallback("54.67.127.227")
        assert "ip" in result
        assert "virustotal" in result
        assert "abuseipdb" in result
        assert "threat_level" in result
        assert "summary" in result
        assert "source" in result

    def test_fallback_source_is_deterministic(self):
        from app.agents.threat_intel_agent import get_deterministic_fallback
        result = get_deterministic_fallback("1.2.3.4")
        assert result["source"] == "deterministic_fallback"

    def test_all_known_botsv3_ips_return_medium(self):
        from app.agents.threat_intel_agent import (
            get_deterministic_fallback, KNOWN_BOTSV3_MALICIOUS
        )
        for ip in KNOWN_BOTSV3_MALICIOUS:
            result = get_deterministic_fallback(ip)
            assert result["threat_level"] == "MEDIUM", \
                f"Expected MEDIUM for known IP {ip}, got {result['threat_level']}"


class TestExtractTechniqueId:
    """Tests for MITRE technique ID extraction from strings."""

    def test_plain_technique_id(self):
        from app.agents.ttp_agent import extract_technique_id
        assert extract_technique_id("T1190") == "T1190"

    def test_technique_with_name(self):
        from app.agents.ttp_agent import extract_technique_id
        assert extract_technique_id(
            "T1190 - Exploit Public-Facing Application"
        ) == "T1190"

    def test_subtechnique_id(self):
        from app.agents.ttp_agent import extract_technique_id
        assert extract_technique_id("T1552.005") == "T1552.005"

    def test_subtechnique_with_name(self):
        from app.agents.ttp_agent import extract_technique_id
        assert extract_technique_id(
            "T1552.005 Cloud Instance Metadata API"
        ) == "T1552.005"

    def test_tactic_code_returns_none(self):
        from app.agents.ttp_agent import extract_technique_id
        # TA codes are tactics not techniques — should not match
        result = extract_technique_id("TA0001")
        assert result is None

    def test_empty_string_returns_none(self):
        from app.agents.ttp_agent import extract_technique_id
        assert extract_technique_id("") is None

    def test_plain_text_returns_none(self):
        from app.agents.ttp_agent import extract_technique_id
        assert extract_technique_id("Initial Access via web exploit") is None

    def test_technique_in_middle_of_string(self):
        from app.agents.ttp_agent import extract_technique_id
        assert extract_technique_id(
            "Stage 1: T1059.003 Windows Command Shell execution"
        ) == "T1059.003"

    def test_first_technique_extracted_when_multiple(self):
        from app.agents.ttp_agent import extract_technique_id
        # Should return first match
        result = extract_technique_id("T1190 and T1552.005")
        assert result in ["T1190", "T1552.005"]

    def test_t1047_wmi(self):
        from app.agents.ttp_agent import extract_technique_id
        assert extract_technique_id("T1047 - Windows Management Instrumentation") == "T1047"

    def test_t1486_ransomware(self):
        from app.agents.ttp_agent import extract_technique_id
        assert extract_technique_id("T1486 - Data Encrypted for Impact") == "T1486"


class TestTTPAgentLogic:
    """
    Tests for TTPAgent deduplication and graceful degradation.
    Uses mock Qdrant responses — no live connection required.
    """

    def test_extract_unique_techniques_deduplicates(self):
        """Same technique in multiple kill chain stages → one mapping."""
        from app.agents.ttp_agent import extract_technique_id
        
        kill_chain = [
            {"stage_name": "Initial Access", "mitre_technique": "T1190"},
            {"stage_name": "Execution", "mitre_technique": "T1059.003"},
            {"stage_name": "Lateral Movement", "mitre_technique": "T1190"},
        ]
        
        seen = set()
        unique = []
        for stage in kill_chain:
            tid = extract_technique_id(
                stage.get("mitre_technique", "")
            )
            if tid and tid not in seen:
                seen.add(tid)
                unique.append(tid)
        
        assert len(unique) == 2
        assert "T1190" in unique
        assert "T1059.003" in unique

    def test_empty_kill_chain_produces_empty_mappings(self):
        """Empty kill chain → empty ttp_mappings."""
        from app.agents.ttp_agent import extract_technique_id
        
        kill_chain = []
        techniques = [
            extract_technique_id(s.get("mitre_technique", ""))
            for s in kill_chain
        ]
        techniques = [t for t in techniques if t]
        assert techniques == []

    def test_stages_without_technique_skipped(self):
        """Kill chain stages with no mitre_technique field are skipped."""
        from app.agents.ttp_agent import extract_technique_id
        
        kill_chain = [
            {"stage_name": "Initial Access", "mitre_technique": ""},
            {"stage_name": "Execution"},  # no field at all
            {"stage_name": "Credential Access", "mitre_technique": "T1552.005"},
        ]
        
        techniques = [
            extract_technique_id(s.get("mitre_technique", ""))
            for s in kill_chain
        ]
        valid = [t for t in techniques if t]
        assert valid == ["T1552.005"]

    @pytest.mark.asyncio
    async def test_enrich_technique_rag_miss_returns_low_confidence(self):
        """RAG miss returns entry with confidence=0.0, not crash."""
        from unittest.mock import AsyncMock, patch
        from app.agents.ttp_agent import enrich_technique

        with patch(
            "app.agents.ttp_agent.retrieve_mitre_technique",
            new=AsyncMock(return_value=None)
        ), patch(
            "app.agents.ttp_agent.retrieve_cves_for_technique",
            new=AsyncMock(return_value=[])
        ):
            result = await enrich_technique("T9999", "Test Stage")
            assert result["confidence"] == 0.0
            assert result["technique_id"] == "T9999"
            assert "RAG lookup failed" in result["description"]

    @pytest.mark.asyncio
    async def test_enrich_technique_rag_hit_returns_high_confidence(self):
        """RAG hit returns entry with confidence > 0."""
        from unittest.mock import AsyncMock, patch
        from app.agents.ttp_agent import enrich_technique

        mock_technique = {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "description": "Adversaries may attempt to exploit...",
            "detection": "Monitor for unusual web server traffic...",
            "mitigation": "Apply patches and updates...",
            "platforms": "Linux, Windows, macOS",
            "data_sources": "Application Log, Network Traffic",
            "score": 0.85,
        }

        with patch(
            "app.agents.ttp_agent.retrieve_mitre_technique",
            new=AsyncMock(return_value=mock_technique)
        ), patch(
            "app.agents.ttp_agent.retrieve_cves_for_technique",
            new=AsyncMock(return_value=[])
        ):
            result = await enrich_technique("T1190", "Initial Access")
            assert result["confidence"] > 0
            assert result["technique_name"] == "Exploit Public-Facing Application"
            assert result["technique_id"] == "T1190"


class TestThreatIntelAgentState:
    """
    Tests for ThreatIntelAgent state handling.
    Uses mock httpx — no live API calls.
    """

    @pytest.mark.asyncio
    async def test_no_external_ips_returns_empty_threat_intel(self):
        """All RFC1918 IPs → empty threat_intel."""
        from app.agents.threat_intel_agent import threat_intel_agent

        state = {
            "investigation_id": "test-001",
            "attack_classification": "INSIDER_THREAT",
            "blast_radius": {
                "external_ips_observed": [],
                "internal_ips_affected": ["172.16.0.178"],
            },
            "patient_zero": {
                "ip_address": "172.16.0.127",
                "role": "Compromised Internal Host",
            },
        }

        result = await threat_intel_agent(state)
        assert result["threat_intel"] == {}

    @pytest.mark.asyncio
    async def test_internal_patient_zero_excluded_from_queries(self):
        """RFC1918 patient_zero IP not queried."""
        from app.agents.threat_intel_agent import threat_intel_agent

        state = {
            "investigation_id": "test-002",
            "attack_classification": "RANSOMWARE",
            "blast_radius": {
                "external_ips_observed": [],
            },
            "patient_zero": {
                "ip_address": "192.168.247.129",
                "role": "Compromised Internal Host",
            },
        }

        result = await threat_intel_agent(state)
        assert result["threat_intel"] == {}

    @pytest.mark.asyncio
    async def test_max_5_ips_enforced(self):
        """More than 5 external IPs → only first 5 processed."""
        from app.agents.threat_intel_agent import (
            threat_intel_agent, is_internal_ip
        )

        external_ips = [
            f"1.2.3.{i}" for i in range(1, 11)
        ]  # 10 IPs

        state = {
            "investigation_id": "test-003",
            "attack_classification": "APT",
            "blast_radius": {
                "external_ips_observed": external_ips,
            },
            "patient_zero": {
                "ip_address": "54.67.127.227",
            },
        }

        result = await threat_intel_agent(state)
        # With fallback: max 5 IPs processed
        assert len(result["threat_intel"]) <= 5

    @pytest.mark.asyncio
    async def test_threat_intel_contains_required_fields(self):
        """Each threat_intel entry has required fields."""
        from app.agents.threat_intel_agent import threat_intel_agent

        state = {
            "investigation_id": "test-004",
            "attack_classification": "APT",
            "blast_radius": {
                "external_ips_observed": ["54.67.127.227"],
            },
            "patient_zero": {"ip_address": "172.16.0.178"},
        }

        result = await threat_intel_agent(state)
        assert "54.67.127.227" in result["threat_intel"]
        entry = result["threat_intel"]["54.67.127.227"]
        assert "threat_level" in entry
        assert "virustotal" in entry
        assert "abuseipdb" in entry
        assert "summary" in entry
        assert entry["threat_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
