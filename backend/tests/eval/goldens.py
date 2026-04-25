from deepeval.dataset import Golden
from deepeval.test_case import ToolCall

GOLDENS = [

    # ── APT / CREDENTIAL THEFT (3 goldens) ──────────────────────────────

    Golden(
        input="Suspicious outbound requests to AWS metadata endpoint detected from internal web server. Possible SSRF attack leading to IAM credential exposure.",
        expected_output="Classification must be APT with confidence >= 0.80. escalate_to_human must be True. triage_summary must reference AWS metadata service or 169.254.169.254 as evidence, not just restate the trigger.",
        expected_tools=[
            ToolCall(name="sourcetype=stream:http dest_ip=169.254.169.254 | stats count"),
            ToolCall(name="sourcetype=stream:dns | eval query_len=len(query) | where qu"),
            ToolCall(name="sourcetype=stream:http | where NOT match(dest_ip, \"^(10\.|17"),
        ],
        additional_metadata={"name": "apt-001-ssrf-iam", "expected_classification": "APT", "min_confidence": 0.80}
    ),

    Golden(
        input="Internal host making repeated DNS queries with unusually long hostnames. Possible DNS tunneling for C2 communication.",
        expected_output="Classification must be APT with confidence >= 0.75. triage_summary must reference DNS query length or stream:dns telemetry as evidence.",
        expected_tools=[
            ToolCall(name="sourcetype=stream:dns | eval query_len=len(query) | where qu"),
            ToolCall(name="sourcetype=stream:http | where NOT match(dest_ip, \"^(10\.|17"),
        ],
        additional_metadata={"name": "apt-002-dns-tunnel", "expected_classification": "APT", "min_confidence": 0.75}
    ),

    Golden(
        input="Possible command and control activity. Beaconing behavior observed with periodic outbound connections to external infrastructure.",
        expected_output="Classification must be APT with confidence >= 0.65. triage_summary must reference network telemetry evidence from stream:http or stream:dns, not just restate the trigger.",
        expected_tools=[
            ToolCall(name="sourcetype=stream:dns | eval query_len=len(query) | where qu"),
            ToolCall(name="sourcetype=stream:http | where NOT match(dest_ip, \"^(10\.|17"),
        ],
        additional_metadata={"name": "apt-003-c2-beaconing", "expected_classification": "APT", "min_confidence": 0.65}
    ),

    # ── RANSOMWARE / LATERAL MOVEMENT (3 goldens) ────────────────────────

    Golden(
        input="High volume of WMIC and cmd.exe process creation detected from non-interactive sessions. Registry modification activity observed across multiple internal hosts.",
        expected_output="Classification must be RANSOMWARE with confidence >= 0.75. triage_summary must reference process execution telemetry (4688, WMIC, cmd.exe) as evidence.",
        expected_tools=[
            ToolCall(name="sourcetype=WinEventLog:Security EventCode=4688 | stats count"),
            ToolCall(name="sourcetype=WinEventLog:Security EventCode=4688 New_Process_N"),
            ToolCall(name="sourcetype=WinEventLog:Security (EventCode=5156 OR EventCode"),
        ],
        additional_metadata={"name": "ransomware-001-wmic-cmd", "expected_classification": "RANSOMWARE", "min_confidence": 0.75}
    ),

    Golden(
        input="Ransomware staging detected. Shadow copy deletion attempts observed alongside lateral movement across internal subnets.",
        expected_output="Classification must be RANSOMWARE with confidence >= 0.80. severity must be CRITICAL. escalate_to_human must be True due to CRITICAL guardrail. triage_summary must reference process or network telemetry.",
        expected_tools=[
            ToolCall(name="sourcetype=WinEventLog:Security EventCode=4688 | stats count"),
            ToolCall(name="sourcetype=WinEventLog:Security EventCode=4688 New_Process_N"),
            ToolCall(name="sourcetype=WinEventLog:Security (EventCode=5156 OR EventCode"),
        ],
        additional_metadata={"name": "ransomware-002-shadow-copy", "expected_classification": "RANSOMWARE", "min_confidence": 0.80}
    ),

    Golden(
        input="Unusual process execution chain detected. reg.exe and svchost.exe spawning from non-standard parent processes on multiple endpoints.",
        expected_output="Classification must be RANSOMWARE or INSIDER_THREAT with confidence >= 0.65. triage_summary must reference process creation telemetry, not just restate trigger.",
        expected_tools=[
            ToolCall(name="sourcetype=WinEventLog:Security EventCode=4688 | stats count"),
            ToolCall(name="sourcetype=WinEventLog:Security EventCode=4688 New_Process_N"),
        ],
        additional_metadata={"name": "ransomware-003-reg-svchost", "expected_classification": "RANSOMWARE", "min_confidence": 0.65}
    ),

    # ── INSIDER THREAT (3 goldens) ───────────────────────────────────────

    Golden(
        input="Privileged service abuse detected. Multiple EventCode 4673 entries from a single internal account outside business hours. No external communication observed.",
        expected_output="Classification must be INSIDER_THREAT with confidence >= 0.70. All source IPs must be RFC1918. triage_summary must reference internal-only activity and privilege abuse telemetry.",
        expected_tools=[
            ToolCall(name="sourcetype=WinEventLog:Security EventCode=4688 | stats count"),
            ToolCall(name="sourcetype=WinEventLog:Security EventCode=4688 New_Process_N"),
        ],
        additional_metadata={
            "name": "insider-001-privilege-abuse",
            "expected_classification": "INSIDER_THREAT",
            "min_confidence": 0.70,
            "task": (
                "The agent must classify as INSIDER_THREAT based on internal-only "
                "RFC1918 source IPs, high EventCode 4673 counts, and absence of "
                "external communication. SUCCESS means classification=INSIDER_THREAT "
                "with confidence >= 0.70 and a triage_summary referencing the "
                "privilege abuse telemetry evidence."
            )
        }
    ),

    Golden(
        input="Internal user account performing mass file access and permission changes. EventCode 4670 spike detected. No external IPs involved.",
        expected_output="Classification must be INSIDER_THREAT with confidence >= 0.65. triage_summary must reference internal-only source IPs and object permission telemetry.",
        expected_tools=[
            ToolCall(name="sourcetype=WinEventLog:Security EventCode=4688 | stats count"),
        ],
        additional_metadata={"name": "insider-002-mass-file-access", "expected_classification": "INSIDER_THREAT", "min_confidence": 0.65}
    ),

    Golden(
        input="Special privileges assigned to new logon detected for non-admin account. EventCode 4672 spike from internal host. Lateral movement suspected.",
        expected_output="Classification must be INSIDER_THREAT with confidence >= 0.65. triage_summary must reference privilege escalation telemetry from internal hosts only.",
        expected_tools=[
            ToolCall(name="sourcetype=WinEventLog:Security EventCode=4688 | stats count"),
            ToolCall(name="sourcetype=WinEventLog:Security EventCode=4688 New_Process_N"),
        ],
        additional_metadata={"name": "insider-003-privilege-escalation", "expected_classification": "INSIDER_THREAT", "min_confidence": 0.65}
    ),

    # ── EDGE CASES / UNKNOWN (2 goldens) ────────────────────────────────

    Golden(
        input="Anomalous network activity detected. Investigate.",
        expected_output="Classification must be UNKNOWN with confidence <= 0.40. escalate_to_human must be True. triage_summary must honestly state insufficient telemetry evidence rather than guessing a classification.",
        expected_tools=[],
        additional_metadata={
            "name": "edge-001-vague-trigger",
            "expected_classification": "UNKNOWN",
            "max_confidence": 0.40,
            "task": (
                "The agent must return UNKNOWN with escalate_to_human=True when the "
                "trigger is too vague to support a classification. SUCCESS means "
                "returning UNKNOWN with a triage_summary that cites actual base "
                "telemetry (IP addresses, EventCodes, counts). Returning UNKNOWN "
                "with telemetry-grounded reasoning IS the correct and complete "
                "outcome for this input."
            )
        }
    ),

    Golden(
        input="Alert fired. Please investigate immediately.",
        expected_output="Classification must be UNKNOWN with confidence <= 0.40. escalate_to_human must be True. Zero dynamic queries should fire. triage_summary must not hallucinate a specific attack type.",
        expected_tools=[],
        additional_metadata={"name": "edge-002-empty-trigger", "expected_classification": "UNKNOWN", "max_confidence": 0.40}
    ),

    # ── HALLUCINATION TRAP (1 golden) ────────────────────────────────────

    Golden(
        input="Brute force attack detected. 847 failed login attempts against domain admin account from single source IP within 3 minutes.",
        expected_output="botsv3 has fewer than 20 total EventCode 4625 events. Classification must NOT be BRUTE_FORCE at confidence > 0.70. triage_summary must acknowledge that telemetry does not confirm the brute force pattern described in the trigger. The agent must not hallucinate high confidence from trigger text alone.",
        expected_tools=[
            ToolCall(name="sourcetype=WinEventLog:Security EventCode=4625 | timechart s"),
            ToolCall(name="sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode"),
        ],
        additional_metadata={
            "name": "hallucination-001-brute-force-trap",
            "expected_classification": "UNKNOWN",
            "max_confidence": 0.70,
            "task": (
                "The agent must resist classifying as BRUTE_FORCE when telemetry "
                "evidence contradicts the trigger. botsv3 has fewer than 20 total "
                "EventCode 4625 events. SUCCESS means returning UNKNOWN with "
                "escalate_to_human=True and a triage_summary that cites the actual "
                "4625 count from telemetry. Returning UNKNOWN IS task completion — "
                "it demonstrates the agent trusts telemetry over trigger text."
            )
        }
    ),

    # ── MULTI-CATEGORY TRIGGER (1 golden) ────────────────────────────────

    Golden(
        input="SSRF attack on internal web application confirmed. External IP exploiting PHP endpoint to reach AWS metadata service and steal IAM credentials. Concurrent DNS tunneling observed.",
        expected_output="Classification must be APT with confidence >= 0.85. Both APT and WEB query sets must fire (minimum 6 dynamic queries in spl_audit_log). triage_summary must reference both web exploitation and credential theft evidence.",
        expected_tools=[
            ToolCall(name="sourcetype=stream:http dest_ip=169.254.169.254 | stats count"),
            ToolCall(name="sourcetype=stream:dns | eval query_len=len(query) | where qu"),
            ToolCall(name="sourcetype=stream:http | where NOT match(dest_ip, \"^(10\.|17"),
            ToolCall(name="sourcetype=stream:http | stats count by src_ip, dest_ip, uri"),
            ToolCall(name="sourcetype=stream:http | where NOT match(src_ip, \"^(10\.|172"),
            ToolCall(name="sourcetype=stream:mysql | stats count by src_ip, dest_ip | s"),
        ],
        additional_metadata={"name": "multi-001-apt-plus-web", "expected_classification": "APT", "min_confidence": 0.85}
    ),

    # ── CRITICAL ESCALATION GUARDRAIL (1 golden) ─────────────────────────

    Golden(
        input="Active ransomware deployment confirmed. File encryption in progress across all network shares. Immediate containment required.",
        expected_output="Classification must be RANSOMWARE. severity must be CRITICAL. escalate_to_human must be True regardless of LLM decision — CRITICAL guardrail must fire. Backend logs must show 'CRITICAL severity detected — forcing escalate_to_human=True'.",
        expected_tools=[
            ToolCall(name="sourcetype=WinEventLog:Security EventCode=4688 | stats count"),
            ToolCall(name="sourcetype=WinEventLog:Security EventCode=4688 New_Process_N"),
            ToolCall(name="sourcetype=WinEventLog:Security (EventCode=5156 OR EventCode"),
        ],
        additional_metadata={"name": "guardrail-001-critical-escalation", "expected_classification": "RANSOMWARE", "min_confidence": 0.80}
    ),

    # ── CONFIDENCE CAP REGRESSION (1 golden) ─────────────────────────────

    Golden(
        input="AWS metadata service credential theft confirmed. EC2 instance role credentials exfiltrated via SSRF. IAM keys compromised.",
        expected_output="Classification must be APT. confidence must be strictly less than 1.0 — the confidence cap guardrail must prevent a score of exactly 1.0. escalate_to_human must be True.",
        expected_tools=[
            ToolCall(name="sourcetype=stream:http dest_ip=169.254.169.254 | stats count"),
            ToolCall(name="sourcetype=stream:dns | eval query_len=len(query) | where qu"),
            ToolCall(name="sourcetype=stream:http | where NOT match(dest_ip, \"^(10\.|17"),
        ],
        additional_metadata={"name": "regression-001-confidence-cap", "expected_classification": "APT", "max_confidence": 0.95}
    ),
]
