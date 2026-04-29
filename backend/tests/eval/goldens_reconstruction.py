"""
Ground-truth goldens for ReconstructionAgent DeepEval evaluation.
10 goldens covering APT, RANSOMWARE, INSIDER_THREAT, hallucination
trap, and UNKNOWN bypass.

botsv3 ground truth (from forensic analysis):
- APT attack: SSRF via web app → AWS metadata credential theft
  Real external IPs: 54.67.127.227, 184.85.20.125, 23.73.195.90
  Real internal SSRF source: 172.16.0.127, 172.31.12.76
  Real URI: /latest/meta-data/iam/security-credentials/EC2InstanceRole
  Real EventCode 1102: Security log cleared on BSTOLL-L
- RANSOMWARE: cmd.exe (1091), WMIC.exe (536), reg.exe (523)
  EventCode 4688 dominant, 5156/5157 network filtering
- INSIDER_THREAT: EventCode 4673 (4122), 4670 (3618), 4672 (419)
  All RFC1918 source IPs, no external HTTP/DNS anomalies
"""

from deepeval.dataset import Golden


RECONSTRUCTION_GOLDENS = [

    # ── APT / CREDENTIAL THEFT (3 goldens) ──────────────────────────────

    Golden(
        input="Suspicious outbound requests to AWS metadata endpoint "
              "detected from internal web server. Possible SSRF attack "
              "leading to IAM credential exposure.",
        expected_output=(
            "Kill chain must include at minimum: (1) an Initial Access or "
            "SSRF stage citing 169.254.169.254 or AWS metadata service as "
            "evidence with a CONFIRMED confidence, (2) a Credential Access "
            "stage citing IAM credentials or EC2InstanceRole, (3) at least "
            "one stage with a specific timestamp from 2018-08-20. "
            "patient_zero must be identified — either an external IP "
            "or the internal SSRF source (172.16.0.127 or 172.31.12.76). "
            "blast_radius.containment_priority must be IMMEDIATE. "
            "attack_narrative must mention SSRF and credential theft "
            "with specific evidence. "
            "kill_chain must NOT be empty."
        ),
        additional_metadata={
            "name": "apt-001-ssrf-credential-theft",
            "expected_classification": "APT",
            "required_mitre_tactics": ["TA0001", "TA0006"],
            "required_evidence_keywords": [
                "169.254.169.254", "metadata", "credential", "IAM"
            ],
            "containment_priority": "IMMEDIATE",
            "patient_zero_must_not_be_empty": True,
        }
    ),

    Golden(
        input="Internal host making repeated DNS queries with unusually "
              "long hostnames. Possible DNS tunneling for C2 communication. "
              "Concurrent AWS metadata service access observed.",
        expected_output=(
            "Kill chain must include a Discovery or C2 stage citing "
            "stream:dns evidence with long query lengths or specific "
            "domain names. Must include an Initial Access or Credential "
            "Access stage citing 169.254.169.254. "
            "At least 2 stages must be CONFIRMED. "
            "blast_radius must list at least 2 internal IPs. "
            "attack_narrative must reference DNS and credential access."
        ),
        additional_metadata={
            "name": "apt-002-dns-tunnel-c2",
            "expected_classification": "APT",
            "required_mitre_tactics": ["TA0006", "TA0010"],
            "required_evidence_keywords": ["dns", "query", "metadata"],
            "containment_priority": "IMMEDIATE",
            "patient_zero_must_not_be_empty": True,
        }
    ),

    Golden(
        input="SSRF attack confirmed. External IP exploiting PHP endpoint "
              "to reach AWS metadata service. IAM credentials exfiltrated. "
              "Concurrent DNS tunneling and process execution observed.",
        expected_output=(
            "Kill chain must have >= 4 stages covering: Initial Access "
            "(external IP or web exploit), Credential Access (metadata "
            "service), Execution (process creation EventCode 4688), and "
            "at least one additional stage. "
            "patient_zero evidence must cite a specific timestamp. "
            "blast_radius.data_at_risk must specifically name IAM "
            "credentials or EC2InstanceRole — generic 'data at risk' "
            "statements are insufficient. "
            "attack_narrative must be 2-3 sentences minimum."
        ),
        additional_metadata={
            "name": "apt-003-full-kill-chain",
            "expected_classification": "APT",
            "required_mitre_tactics": ["TA0001", "TA0006", "TA0002"],
            "required_evidence_keywords": [
                "169.254.169.254", "IAM", "4688", "credential"
            ],
            "containment_priority": "IMMEDIATE",
            "min_kill_chain_stages": 4,
        }
    ),

    # ── RANSOMWARE (3 goldens) ───────────────────────────────────────────

    Golden(
        input="High volume of WMIC and cmd.exe process creation detected "
              "from non-interactive sessions. Registry modification "
              "activity observed across multiple internal hosts.",
        expected_output=(
            "Kill chain must include an Execution stage citing EventCode "
            "4688 with WMIC.exe or cmd.exe with specific counts as "
            "evidence. Must include at least one CONFIRMED stage. "
            "patient_zero must be an internal RFC1918 IP with role "
            "'Compromised Internal Host' — ransomware spreads internally. "
            "blast_radius.containment_priority must be IMMEDIATE or HIGH. "
            "attack_narrative must mention process execution evidence."
        ),
        additional_metadata={
            "name": "ransomware-001-wmic-cmd",
            "expected_classification": "RANSOMWARE",
            "required_mitre_tactics": ["TA0002"],
            "required_evidence_keywords": ["4688", "WMIC", "cmd.exe"],
            "patient_zero_role": "Compromised Internal Host",
        }
    ),

    Golden(
        input="Ransomware staging detected. Shadow copy deletion attempts "
              "observed. Registry modification and lateral movement across "
              "internal subnets confirmed.",
        expected_output=(
            "Kill chain must include Execution (4688 process creation) "
            "and Impact or Defense Evasion stage. "
            "At least one stage must cite WMIC.exe, reg.exe, or cmd.exe "
            "with specific event counts. "
            "blast_radius.containment_priority must be IMMEDIATE. "
            "blast_radius.internal_ips_affected must have >= 3 IPs. "
            "attack_narrative must mention ransomware and containment."
        ),
        additional_metadata={
            "name": "ransomware-002-shadow-copy",
            "expected_classification": "RANSOMWARE",
            "required_mitre_tactics": ["TA0002", "TA0040"],
            "required_evidence_keywords": ["4688", "reg.exe"],
            "containment_priority": "IMMEDIATE",
        }
    ),

    Golden(
        input="Active ransomware deployment confirmed. File encryption "
              "in progress across all network shares. cmd.exe and reg.exe "
              "spawning from non-interactive sessions. Immediate containment required.",
        expected_output=(
            "Kill chain must have >= 3 stages. Must include at minimum "
            "Execution (4688) and Impact (TA0040) stages. "
            "Every stage evidence field must cite a specific EventCode, "
            "process name with count, or IP address — generic statements "
            "like 'suspicious activity' are insufficient evidence. "
            "blast_radius.containment_priority must be IMMEDIATE. "
            "reconstruction_confidence must be > 0 — cannot be 0.0."
        ),
        additional_metadata={
            "name": "ransomware-003-active-deployment",
            "expected_classification": "RANSOMWARE",
            "required_mitre_tactics": ["TA0002", "TA0040"],
            "required_evidence_keywords": ["4688", "cmd.exe"],
            "containment_priority": "IMMEDIATE",
            "min_kill_chain_stages": 3,
        }
    ),

    # ── INSIDER THREAT (2 goldens) ───────────────────────────────────────

    Golden(
        input="Privileged service abuse detected. Multiple EventCode 4673 "
              "entries from single internal account outside business hours. "
              "No external communication observed.",
        expected_output=(
            "Kill chain must include a Privilege Escalation or "
            "Credential Access stage citing EventCode 4673 with count. "
            "patient_zero must be an internal RFC1918 IP with role "
            "'Compromised Internal Host'. "
            "blast_radius.external_ips_observed must be empty [] — "
            "insider threat has no external IPs. "
            "attack_narrative must reference internal-only activity."
        ),
        additional_metadata={
            "name": "insider-001-privilege-abuse",
            "expected_classification": "INSIDER_THREAT",
            "required_mitre_tactics": ["TA0004"],
            "required_evidence_keywords": ["4673", "internal", "RFC1918"],
            "patient_zero_role": "Compromised Internal Host",
            "no_external_ips": True,
        }
    ),

    Golden(
        input="Internal user performing mass file access and permission "
              "changes. EventCode 4670 spike. No external IPs involved. "
              "Special privileges assigned to non-admin account.",
        expected_output=(
            "Kill chain must cite EventCode 4670 or 4672 as evidence "
            "in at least one stage. "
            "patient_zero role must be 'Compromised Internal Host'. "
            "attack_narrative must not mention external attackers or "
            "SSRF — this is a pure insider threat scenario. "
            "blast_radius.containment_priority must be HIGH or MEDIUM "
            "for insider threat — not IMMEDIATE unless severity CRITICAL."
        ),
        additional_metadata={
            "name": "insider-002-mass-file-access",
            "expected_classification": "INSIDER_THREAT",
            "required_mitre_tactics": ["TA0004", "TA0009"],
            "required_evidence_keywords": ["4670", "4672"],
            "patient_zero_role": "Compromised Internal Host",
        }
    ),

    # ── HALLUCINATION TRAP (1 golden) ────────────────────────────────────

    Golden(
        input="Advanced persistent threat detected. Sophisticated multi-stage "
              "attack including zero-day exploit, polymorphic malware, "
              "satellite uplink data exfiltration, and quantum encryption "
              "bypass observed across 47 countries.",
        expected_output=(
            "The agent must NOT hallucinate attack stages not present in "
            "botsv3 telemetry. Specifically: no stages citing 'zero-day "
            "exploit', 'polymorphic malware', 'satellite uplink', "
            "'quantum encryption', or '47 countries'. "
            "Kill chain stages must only cite evidence from actual "
            "botsv3 telemetry: stream:http, stream:dns, WinEventLog, "
            "EventCodes 4688/4673/4670/4625/5156. "
            "If telemetry does not support a claimed stage, confidence "
            "must be INFERRED not CONFIRMED. "
            "attack_narrative must be grounded in actual telemetry."
        ),
        additional_metadata={
            "name": "hallucination-trap-001",
            "expected_classification": "APT",
            "forbidden_evidence_keywords": [
                "zero-day", "polymorphic", "satellite", "quantum", 
                "47 countries"
            ],
            "faithfulness_critical": True,
        }
    ),

    # ── UNKNOWN BYPASS (1 golden) ────────────────────────────────────────

    Golden(
        input="Alert fired. Please investigate immediately.",
        expected_output=(
            "The reconstruction agent must NOT be called for this trigger. "
            "kill_chain must be empty []. "
            "patient_zero must be empty {}. "
            "blast_radius must be empty {}. "
            "attack_narrative must be empty string or null. "
            "react_iterations must be 0 or absent. "
            "Backend logs must show routing to END after triage, "
            "not reconstruction_agent."
        ),
        additional_metadata={
            "name": "unknown-bypass-001",
            "expected_classification": "UNKNOWN",
            "reconstruction_must_not_run": True,
        }
    ),
]
