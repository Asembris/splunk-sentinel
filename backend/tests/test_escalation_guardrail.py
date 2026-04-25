import pytest
from app.agents.triage_agent import TriageResult, apply_escalation_guardrail

class TestCriticalEscalationGuardrail:
    def test_critical_severity_forces_escalation(self):
        result = TriageResult(
            attack_classification="APT",
            severity="CRITICAL",
            classification_confidence=0.95,
            triage_summary="SSRF confirmed. IAM credentials exposed.",
            escalate_to_human=False,  # LLM said false
            key_indicators=["AWS metadata queried"]
        )
        patched = apply_escalation_guardrail(result)
        assert patched.escalate_to_human is True

    def test_critical_overrides_llm_false(self):
        """Even if LLM sets escalate_to_human=False, CRITICAL must override it."""
        result = TriageResult(
            attack_classification="RANSOMWARE",
            severity="CRITICAL",
            classification_confidence=1.0,
            triage_summary="Full ransomware kill chain confirmed.",
            escalate_to_human=False,
            key_indicators=["WMIC", "cmd.exe", "shadow copy deletion"]
        )
        patched = apply_escalation_guardrail(result)
        assert patched.escalate_to_human is True

    def test_high_severity_does_not_force_escalation(self):
        result = TriageResult(
            attack_classification="RANSOMWARE",
            severity="HIGH",
            classification_confidence=0.80,
            triage_summary="Ransomware pattern detected.",
            escalate_to_human=False,
            key_indicators=["WMIC", "cmd.exe"]
        )
        patched = apply_escalation_guardrail(result)
        assert patched.escalate_to_human is False

    def test_low_confidence_unknown_forces_escalation(self):
        """UNKNOWN with confidence < 0.4 must escalate regardless of severity."""
        result = TriageResult(
            attack_classification="UNKNOWN",
            severity="LOW",
            classification_confidence=0.3,
            triage_summary="Insufficient telemetry to classify.",
            escalate_to_human=False,  # LLM said false
            key_indicators=[]
        )
        patched = apply_escalation_guardrail(result)
        assert patched.escalate_to_human is True

    def test_high_confidence_known_classification_no_escalation(self):
        result = TriageResult(
            attack_classification="RANSOMWARE",
            severity="HIGH",
            classification_confidence=0.85,
            triage_summary="Ransomware confirmed via process execution chain.",
            escalate_to_human=False,
            key_indicators=["WMIC", "cmd.exe", "reg.exe"]
        )
        patched = apply_escalation_guardrail(result)
        assert patched.escalate_to_human is False

    def test_medium_severity_respects_llm_decision(self):
        result = TriageResult(
            attack_classification="INSIDER_THREAT",
            severity="MEDIUM",
            classification_confidence=0.65,
            triage_summary="Internal privilege escalation pattern.",
            escalate_to_human=True,  # LLM said true
            key_indicators=["RFC1918 only", "4673 events"]
        )
        patched = apply_escalation_guardrail(result)
        assert patched.escalate_to_human is True


class TestConfidenceCapGuardrail:
    def test_confidence_1_is_capped_at_0_95(self):
        result = TriageResult(
            attack_classification="APT",
            severity="CRITICAL",
            classification_confidence=1.0,
            triage_summary="Definitive APT confirmation.",
            escalate_to_human=True,
            key_indicators=["AWS metadata SSRF"]
        )
        patched = apply_escalation_guardrail(result)
        assert patched.classification_confidence <= 0.95

    def test_confidence_below_1_is_not_modified(self):
        result = TriageResult(
            attack_classification="APT",
            severity="HIGH",
            classification_confidence=0.90,
            triage_summary="Strong APT indicators.",
            escalate_to_human=True,
            key_indicators=["External HTTP", "DNS anomaly"]
        )
        patched = apply_escalation_guardrail(result)
        assert patched.classification_confidence == 0.90
