import pytest
from pydantic import ValidationError
import json

from app.agents.reconstruction_agent import compute_reconstruction_confidence

class TestComputeReconstructionConfidence:
    """
    Tests for the deterministic confidence formula.
    This function is pure Python — no mocks needed.
    """

    def test_zero_confidence_with_no_evidence(self):
        score = compute_reconstruction_confidence(
            confirmed_stages=0,
            total_stages=0,
            sourcetypes_covered=set(),
            has_patient_zero=False,
            has_blast_radius=False,
            has_external_ip=False,
        )
        assert score == 0.0

    def test_sourcetype_breadth_contributes(self):
        # 4 sourcetypes × 0.075 = 0.30 (max from this component)
        score = compute_reconstruction_confidence(
            confirmed_stages=0,
            total_stages=0,
            sourcetypes_covered={"stream:http", "stream:dns",
                                  "WinEventLog:Security", "osquery:results"},
            has_patient_zero=False,
            has_blast_radius=False,
            has_external_ip=False,
        )
        assert score == pytest.approx(0.30, abs=0.01)

    def test_sourcetype_breadth_capped_at_030(self):
        # 10 sourcetypes should still cap at 0.30
        score = compute_reconstruction_confidence(
            confirmed_stages=0,
            total_stages=0,
            sourcetypes_covered={f"src_{i}" for i in range(10)},
            has_patient_zero=False,
            has_blast_radius=False,
            has_external_ip=False,
        )
        assert score == pytest.approx(0.30, abs=0.01)

    def test_kill_chain_completeness_contributes(self):
        # 3/3 confirmed stages = 1.0 ratio × 0.35 = 0.35
        score = compute_reconstruction_confidence(
            confirmed_stages=3,
            total_stages=3,
            sourcetypes_covered=set(),
            has_patient_zero=False,
            has_blast_radius=False,
            has_external_ip=False,
        )
        assert score == pytest.approx(0.35, abs=0.01)

    def test_partial_kill_chain_completeness(self):
        # 2/4 confirmed = 0.5 ratio × 0.35 = 0.175
        score = compute_reconstruction_confidence(
            confirmed_stages=2,
            total_stages=4,
            sourcetypes_covered=set(),
            has_patient_zero=False,
            has_blast_radius=False,
            has_external_ip=False,
        )
        assert score == pytest.approx(0.175, abs=0.01)

    def test_patient_zero_contributes(self):
        score = compute_reconstruction_confidence(
            confirmed_stages=0,
            total_stages=0,
            sourcetypes_covered=set(),
            has_patient_zero=True,
            has_blast_radius=False,
            has_external_ip=False,
        )
        assert score == pytest.approx(0.10, abs=0.01)

    def test_external_ip_contributes(self):
        score = compute_reconstruction_confidence(
            confirmed_stages=0,
            total_stages=0,
            sourcetypes_covered=set(),
            has_patient_zero=False,
            has_blast_radius=False,
            has_external_ip=True,
        )
        assert score == pytest.approx(0.10, abs=0.01)

    def test_blast_radius_contributes(self):
        score = compute_reconstruction_confidence(
            confirmed_stages=0,
            total_stages=0,
            sourcetypes_covered=set(),
            has_patient_zero=False,
            has_blast_radius=True,
            has_external_ip=False,
        )
        assert score == pytest.approx(0.15, abs=0.01)

    def test_full_evidence_approaches_095(self):
        # Max possible: 0.30 + 0.35 + 0.10 + 0.10 + 0.15 = 1.00 → capped at 0.95
        score = compute_reconstruction_confidence(
            confirmed_stages=5,
            total_stages=5,
            sourcetypes_covered={"a", "b", "c", "d", "e"},
            has_patient_zero=True,
            has_blast_radius=True,
            has_external_ip=True,
        )
        assert score == pytest.approx(0.95, abs=0.01)

    def test_confidence_never_exceeds_095(self):
        # Even with perfect everything, cap at 0.95
        score = compute_reconstruction_confidence(
            confirmed_stages=100,
            total_stages=100,
            sourcetypes_covered={f"s{i}" for i in range(50)},
            has_patient_zero=True,
            has_blast_radius=True,
            has_external_ip=True,
        )
        assert score <= 0.95

    def test_confidence_rounded_to_3_decimals(self):
        score = compute_reconstruction_confidence(
            confirmed_stages=1,
            total_stages=3,
            sourcetypes_covered={"stream:http"},
            has_patient_zero=False,
            has_blast_radius=False,
            has_external_ip=False,
        )
        # Result should be rounded to 3 decimal places
        assert score == round(score, 3)


class TestKillChainStageModel:
    def test_valid_confirmed_stage(self):
        from app.agents.reconstruction_agent import KillChainStage
        stage = KillChainStage(
            stage_number=1,
            stage_name="Initial Access - SSRF",
            mitre_tactic="TA0001",
            mitre_technique="T1190 - Exploit Public-Facing Application",
            timestamp="2018-08-20 11:05:07",
            evidence="IP 172.16.0.127 accessed /latest/meta-data/iam/security-credentials/",
            confidence="CONFIRMED",
            affected_assets=["172.16.0.127"]
        )
        assert stage.confidence == "CONFIRMED"
        assert stage.mitre_tactic == "TA0001"

    def test_valid_inferred_stage(self):
        from app.agents.reconstruction_agent import KillChainStage
        stage = KillChainStage(
            stage_number=2,
            stage_name="Lateral Movement",
            mitre_tactic="TA0008",
            mitre_technique="T1021.002 - SMB",
            timestamp="2018-08-20 11:45:00",
            evidence="Inferred from process execution patterns",
            confidence="INFERRED",
            affected_assets=[]
        )
        assert stage.confidence == "INFERRED"

    def test_rejects_invalid_confidence(self):
        from pydantic import ValidationError
        from app.agents.reconstruction_agent import KillChainStage
        with pytest.raises(ValidationError):
            KillChainStage(
                stage_number=1,
                stage_name="Test",
                mitre_tactic="TA0001",
                mitre_technique="T1190",
                timestamp="2018-08-20",
                evidence="test",
                confidence="SUSPECTED",  # invalid
                affected_assets=[]
            )

    def test_rejects_missing_required_fields(self):
        from pydantic import ValidationError
        from app.agents.reconstruction_agent import KillChainStage
        with pytest.raises(ValidationError):
            KillChainStage(
                stage_number=1,
                stage_name="Test",
                # missing mitre_tactic, mitre_technique, timestamp,
                # evidence, confidence, affected_assets
            )


class TestPatientZeroModel:
    def test_valid_external_attacker(self):
        from app.agents.reconstruction_agent import PatientZero
        pz = PatientZero(
            ip_address="54.67.127.227",
            first_seen="2018-08-20 11:04:18",
            role="External Attacker",
            evidence="First external IP contacting 172.16.0.13 at 11:04:18",
            confidence="CONFIRMED"
        )
        assert pz.role == "External Attacker"
        assert pz.confidence == "CONFIRMED"

    def test_valid_compromised_internal_host(self):
        from app.agents.reconstruction_agent import PatientZero
        pz = PatientZero(
            ip_address="172.16.0.127",
            first_seen="2018-08-20 11:05:07",
            role="Compromised Internal Host",
            evidence="Highest activity internal host with SSRF evidence",
            confidence="INFERRED"
        )
        assert pz.role == "Compromised Internal Host"

    def test_rejects_invalid_confidence(self):
        from pydantic import ValidationError
        from app.agents.reconstruction_agent import PatientZero
        with pytest.raises(ValidationError):
            PatientZero(
                ip_address="10.0.0.1",
                first_seen="2018-08-20",
                role="External Attacker",
                evidence="test",
                confidence="MAYBE"  # invalid
            )


class TestBlastRadiusModel:
    def test_valid_blast_radius(self):
        from app.agents.reconstruction_agent import BlastRadius
        br = BlastRadius(
            total_affected_ips=10,
            internal_ips_affected=["172.16.0.127", "172.16.0.178"],
            external_ips_observed=["54.67.127.227"],
            affected_sourcetypes=["stream:http", "WinEventLog:Security"],
            data_at_risk="IAM credentials via AWS metadata service",
            containment_priority="IMMEDIATE"
        )
        assert br.containment_priority == "IMMEDIATE"
        assert br.total_affected_ips == 10

    def test_rejects_invalid_containment_priority(self):
        from pydantic import ValidationError
        from app.agents.reconstruction_agent import BlastRadius
        with pytest.raises(ValidationError):
            BlastRadius(
                total_affected_ips=5,
                internal_ips_affected=[],
                external_ips_observed=[],
                affected_sourcetypes=[],
                data_at_risk="test",
                containment_priority="URGENT"  # invalid — must be IMMEDIATE/HIGH/MEDIUM/LOW
            )

    def test_all_valid_containment_priorities(self):
        from app.agents.reconstruction_agent import BlastRadius
        for priority in ["IMMEDIATE", "HIGH", "MEDIUM", "LOW"]:
            br = BlastRadius(
                total_affected_ips=1,
                internal_ips_affected=[],
                external_ips_observed=[],
                affected_sourcetypes=[],
                data_at_risk="test",
                containment_priority=priority
            )
            assert br.containment_priority == priority


class TestReconstructionResultModel:
    def test_valid_full_result(self):
        from app.agents.reconstruction_agent import (
            ReconstructionResult, KillChainStage, PatientZero, BlastRadius
        )
        result = ReconstructionResult(
            kill_chain=[
                KillChainStage(
                    stage_number=1,
                    stage_name="Initial Access",
                    mitre_tactic="TA0001",
                    mitre_technique="T1190",
                    timestamp="2018-08-20 11:05:07",
                    evidence="IP 172.16.0.127 accessed metadata service",
                    confidence="CONFIRMED",
                    affected_assets=["172.16.0.127"]
                )
            ],
            patient_zero=PatientZero(
                ip_address="172.16.0.127",
                first_seen="2018-08-20 11:05:07",
                role="Compromised Internal Host",
                evidence="Highest activity internal host",
                confidence="CONFIRMED"
            ),
            blast_radius=BlastRadius(
                total_affected_ips=5,
                internal_ips_affected=["172.16.0.127"],
                external_ips_observed=[],
                affected_sourcetypes=["stream:http"],
                data_at_risk="IAM credentials",
                containment_priority="IMMEDIATE"
            ),
            attack_narrative="APT attack via SSRF. Immediate containment required.",
            reconstruction_confidence=0.75
        )
        assert len(result.kill_chain) == 1
        assert result.reconstruction_confidence == 0.75

    def test_rejects_empty_kill_chain(self):
        from pydantic import ValidationError
        from app.agents.reconstruction_agent import (
            ReconstructionResult, PatientZero, BlastRadius
        )
        with pytest.raises(ValidationError):
            ReconstructionResult(
                kill_chain=[],  # min_length=1
                patient_zero=PatientZero(
                    ip_address="10.0.0.1",
                    first_seen="2018-08-20",
                    role="Compromised Internal Host",
                    evidence="test",
                    confidence="INFERRED"
                ),
                blast_radius=BlastRadius(
                    total_affected_ips=0,
                    internal_ips_affected=[],
                    external_ips_observed=[],
                    affected_sourcetypes=[],
                    data_at_risk="test",
                    containment_priority="LOW"
                ),
                attack_narrative="test",
                reconstruction_confidence=0.5
            )

    def test_rejects_confidence_above_1(self):
        from pydantic import ValidationError
        from app.agents.reconstruction_agent import (
            ReconstructionResult, KillChainStage, PatientZero, BlastRadius
        )
        with pytest.raises(ValidationError):
            ReconstructionResult(
                kill_chain=[KillChainStage(
                    stage_number=1, stage_name="Test",
                    mitre_tactic="TA0001", mitre_technique="T1190",
                    timestamp="2018-08-20", evidence="test",
                    confidence="CONFIRMED", affected_assets=[]
                )],
                patient_zero=PatientZero(
                    ip_address="10.0.0.1", first_seen="2018-08-20",
                    role="Compromised Internal Host", evidence="test",
                    confidence="INFERRED"
                ),
                blast_radius=BlastRadius(
                    total_affected_ips=0, internal_ips_affected=[],
                    external_ips_observed=[], affected_sourcetypes=[],
                    data_at_risk="test", containment_priority="LOW"
                ),
                attack_narrative="test",
                reconstruction_confidence=1.5  # exceeds le=1.0
            )

    def test_rejects_negative_confidence(self):
        from pydantic import ValidationError
        from app.agents.reconstruction_agent import (
            ReconstructionResult, KillChainStage, PatientZero, BlastRadius
        )
        with pytest.raises(ValidationError):
            ReconstructionResult(
                kill_chain=[KillChainStage(
                    stage_number=1, stage_name="Test",
                    mitre_tactic="TA0001", mitre_technique="T1190",
                    timestamp="2018-08-20", evidence="test",
                    confidence="CONFIRMED", affected_assets=[]
                )],
                patient_zero=PatientZero(
                    ip_address="10.0.0.1", first_seen="2018-08-20",
                    role="Compromised Internal Host", evidence="test",
                    confidence="INFERRED"
                ),
                blast_radius=BlastRadius(
                    total_affected_ips=0, internal_ips_affected=[],
                    external_ips_observed=[], affected_sourcetypes=[],
                    data_at_risk="test", containment_priority="LOW"
                ),
                attack_narrative="test",
                reconstruction_confidence=-0.1  # below ge=0.0
            )


class TestPatientZeroRoleCorrection:
    """
    Tests for the guardrail that prevents RFC1918 IPs from being 
    classified as 'External Attacker'.
    This logic lives in reconstruction_agent.py post-processing.
    Extract it as a standalone testable function.
    """

    def test_rfc1918_172_16_corrected_to_internal(self):
        """172.16.x.x must be Compromised Internal Host"""
        from app.agents.reconstruction_agent import correct_patient_zero_role
        from app.agents.reconstruction_agent import PatientZero
        pz = PatientZero(
            ip_address="172.16.0.127",
            first_seen="2018-08-20 11:05:07",
            role="External Attacker",  # wrong
            evidence="test",
            confidence="CONFIRMED"
        )
        corrected = correct_patient_zero_role(pz)
        assert corrected.role == "Compromised Internal Host"

    def test_rfc1918_172_31_corrected_to_internal(self):
        from app.agents.reconstruction_agent import (
            correct_patient_zero_role, PatientZero
        )
        pz_input = PatientZero(
            ip_address="172.31.12.76",
            first_seen="2018-08-20",
            role="External Attacker",
            evidence="test",
            confidence="INFERRED"
        )
        corrected = correct_patient_zero_role(pz_input)
        assert corrected.role == "Compromised Internal Host"

    def test_rfc1918_192_168_corrected_to_internal(self):
        from app.agents.reconstruction_agent import (
            correct_patient_zero_role, PatientZero
        )
        pz = PatientZero(
            ip_address="192.168.3.130",
            first_seen="2018-08-20",
            role="External Attacker",
            evidence="test",
            confidence="INFERRED"
        )
        corrected = correct_patient_zero_role(pz)
        assert corrected.role == "Compromised Internal Host"

    def test_rfc1918_10_x_corrected_to_internal(self):
        from app.agents.reconstruction_agent import (
            correct_patient_zero_role, PatientZero
        )
        pz = PatientZero(
            ip_address="10.0.0.1",
            first_seen="2018-08-20",
            role="External Attacker",
            evidence="test",
            confidence="INFERRED"
        )
        corrected = correct_patient_zero_role(pz)
        assert corrected.role == "Compromised Internal Host"

    def test_external_ip_not_modified(self):
        from app.agents.reconstruction_agent import (
            correct_patient_zero_role, PatientZero
        )
        pz = PatientZero(
            ip_address="54.67.127.227",
            first_seen="2018-08-20",
            role="External Attacker",
            evidence="test",
            confidence="CONFIRMED"
        )
        corrected = correct_patient_zero_role(pz)
        assert corrected.role == "External Attacker"

    def test_internal_role_not_modified_when_already_correct(self):
        from app.agents.reconstruction_agent import (
            correct_patient_zero_role, PatientZero
        )
        pz = PatientZero(
            ip_address="172.16.0.127",
            first_seen="2018-08-20",
            role="Compromised Internal Host",  # already correct
            evidence="test",
            confidence="CONFIRMED"
        )
        corrected = correct_patient_zero_role(pz)
        assert corrected.role == "Compromised Internal Host"

    def test_all_rfc1918_172_ranges_corrected(self):
        """Test all 172.16.x through 172.31.x ranges"""
        from app.agents.reconstruction_agent import (
            correct_patient_zero_role, PatientZero
        )
        for third_octet in range(16, 32):
            pz = PatientZero(
                ip_address=f"172.{third_octet}.0.1",
                first_seen="2018-08-20",
                role="External Attacker",
                evidence="test",
                confidence="INFERRED"
            )
            corrected = correct_patient_zero_role(pz)
            assert corrected.role == "Compromised Internal Host", \
                f"172.{third_octet}.x.x should be internal"


class TestContainmentPriorityGuardrail:
    """
    Tests for the post-processing guardrail that forces IMMEDIATE
    containment for CRITICAL severity + CONFIRMED kill chain stages.
    Extract as standalone testable function: apply_containment_guardrail
    """

    def test_critical_severity_with_confirmed_stage_forces_immediate(self):
        from app.agents.reconstruction_agent import (
            apply_containment_guardrail, BlastRadius, KillChainStage
        )
        br = BlastRadius(
            total_affected_ips=5,
            internal_ips_affected=["172.16.0.1"],
            external_ips_observed=[],
            affected_sourcetypes=["stream:http"],
            data_at_risk="IAM credentials",
            containment_priority="HIGH"  # should be overridden
        )
        kill_chain = [
            KillChainStage(
                stage_number=1, stage_name="Initial Access",
                mitre_tactic="TA0001", mitre_technique="T1190",
                timestamp="2018-08-20", evidence="test",
                confidence="CONFIRMED", affected_assets=[]
            )
        ]
        result = apply_containment_guardrail(br, kill_chain, severity="CRITICAL")
        assert result.containment_priority == "IMMEDIATE"

    def test_critical_severity_all_inferred_does_not_force_immediate(self):
        from app.agents.reconstruction_agent import (
            apply_containment_guardrail, BlastRadius, KillChainStage
        )
        br = BlastRadius(
            total_affected_ips=5,
            internal_ips_affected=[],
            external_ips_observed=[],
            affected_sourcetypes=[],
            data_at_risk="test",
            containment_priority="HIGH"
        )
        kill_chain = [
            KillChainStage(
                stage_number=1, stage_name="Initial Access",
                mitre_tactic="TA0001", mitre_technique="T1190",
                timestamp="2018-08-20", evidence="test",
                confidence="INFERRED",  # no CONFIRMED stages
                affected_assets=[]
            )
        ]
        result = apply_containment_guardrail(br, kill_chain, severity="CRITICAL")
        assert result.containment_priority == "HIGH"  # not overridden

    def test_high_severity_not_forced_to_immediate(self):
        from app.agents.reconstruction_agent import (
            apply_containment_guardrail, BlastRadius, KillChainStage
        )
        br = BlastRadius(
            total_affected_ips=3,
            internal_ips_affected=[],
            external_ips_observed=[],
            affected_sourcetypes=[],
            data_at_risk="test",
            containment_priority="HIGH"
        )
        kill_chain = [
            KillChainStage(
                stage_number=1, stage_name="Execution",
                mitre_tactic="TA0002", mitre_technique="T1059",
                timestamp="2018-08-20", evidence="test",
                confidence="CONFIRMED", affected_assets=[]
            )
        ]
        result = apply_containment_guardrail(br, kill_chain, severity="HIGH")
        assert result.containment_priority == "HIGH"  # not overridden

    def test_existing_immediate_not_downgraded(self):
        from app.agents.reconstruction_agent import (
            apply_containment_guardrail, BlastRadius, KillChainStage
        )
        br = BlastRadius(
            total_affected_ips=1,
            internal_ips_affected=[],
            external_ips_observed=[],
            affected_sourcetypes=[],
            data_at_risk="test",
            containment_priority="IMMEDIATE"
        )
        result = apply_containment_guardrail(br, [], severity="LOW")
        assert result.containment_priority == "IMMEDIATE"


class TestSeedQueryCoverage:
    """
    Tests for SEED_QUERIES dict — ensures all classifications 
    have valid seed queries that meet guardrail requirements.
    """

    def test_all_classifications_have_seed_queries(self):
        from app.agents.reconstruction_agent import SEED_QUERIES
        for classification in ["APT", "RANSOMWARE", 
                                "INSIDER_THREAT", "BRUTE_FORCE", "UNKNOWN"]:
            assert classification in SEED_QUERIES, \
                f"{classification} missing from SEED_QUERIES"
            assert len(SEED_QUERIES[classification]) >= 1, \
                f"{classification} has empty seed query list"

    def test_all_seed_queries_target_botsv3(self):
        from app.agents.reconstruction_agent import SEED_QUERIES
        for classification, queries in SEED_QUERIES.items():
            for q in queries:
                assert "index=botsv3" in q, \
                    f"{classification} query missing index=botsv3: {q[:60]}"

    def test_all_seed_queries_have_time_field(self):
        from app.agents.reconstruction_agent import SEED_QUERIES
        for classification, queries in SEED_QUERIES.items():
            for q in queries:
                assert "strftime" in q or "eval time" in q, \
                    f"{classification} query missing time field: {q[:60]}"

    def test_all_seed_queries_have_head_limit(self):
        from app.agents.reconstruction_agent import SEED_QUERIES
        for classification, queries in SEED_QUERIES.items():
            for q in queries:
                assert "head" in q, \
                    f"{classification} query missing head limit: {q[:60]}"

    def test_apt_seed_queries_cover_external_http(self):
        from app.agents.reconstruction_agent import SEED_QUERIES
        apt_queries = " ".join(SEED_QUERIES["APT"])
        assert "stream:http" in apt_queries
        assert "169.254.169.254" in apt_queries or "NOT match" in apt_queries

    def test_ransomware_seed_queries_cover_process_execution(self):
        from app.agents.reconstruction_agent import SEED_QUERIES
        ransomware_queries = " ".join(SEED_QUERIES["RANSOMWARE"])
        assert "4688" in ransomware_queries  # process creation EventCode

    def test_insider_threat_seed_queries_cover_privilege_events(self):
        from app.agents.reconstruction_agent import SEED_QUERIES
        insider_queries = " ".join(SEED_QUERIES["INSIDER_THREAT"])
        assert "4624" in insider_queries or "4673" in insider_queries

    def test_unknown_fallback_equals_apt(self):
        from app.agents.reconstruction_agent import SEED_QUERIES
        assert SEED_QUERIES["UNKNOWN"] == SEED_QUERIES["APT"]
