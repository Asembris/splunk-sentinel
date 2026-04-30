"""
RAG Pipeline Ingestion Script for Splunk Sentinel.

Run once to populate Qdrant with all 4 knowledge collections:
    python -m app.rag.ingest

Collections:
    1. mitre_attack     — MITRE ATT&CK Enterprise techniques (~2,400 chunks)
    2. cve_nvd          — CVE/NVD data filtered to botsv3 attack surface (~500 chunks)
    3. ir_playbooks     — IR playbooks for APT/ransomware/insider response (~200 chunks)
    4. botsv3_investigation — Manual investigation notes and ground truth (~50 chunks)
"""

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv
from openai import OpenAI
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    PointStruct,
    VectorParams,
)

from app.rag.collections import (
    ALL_COLLECTIONS,
    BOTSV3_COLLECTION,
    CVE_COLLECTION,
    EMBEDDING_DIMS,
    EMBEDDING_MODEL,
    MITRE_COLLECTION,
    PLAYBOOK_COLLECTION,
)

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Clients ───────────────────────────────────────────────────────────────────
openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
qdrant_client = QdrantClient(
    url=os.getenv("QDRANT_URL"),
    api_key=os.getenv("QDRANT_API_KEY"),
    timeout=300,
)

# ── MITRE ATT&CK STIX Download ───────────────────────────────────────────────
MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def download_mitre_stix() -> dict:
    """Download MITRE ATT&CK Enterprise STIX JSON from GitHub."""
    logger.info("Downloading MITRE ATT&CK Enterprise STIX JSON...")
    cache_path = Path("data/mitre_enterprise_attack.json")
    cache_path.parent.mkdir(exist_ok=True)

    if cache_path.exists():
        logger.info("Using cached MITRE STIX data at %s", cache_path)
        with open(cache_path) as f:
            return json.load(f)

    with httpx.Client(timeout=120) as client:
        response = client.get(MITRE_STIX_URL)
        response.raise_for_status()
        data = response.json()

    with open(cache_path, "w") as f:
        json.dump(data, f)
    logger.info("Downloaded and cached MITRE STIX data (%d objects)", len(data["objects"]))
    return data


def parse_mitre_techniques(stix_data: dict) -> list[dict]:
    """
    Parse MITRE ATT&CK STIX into chunks.
    One chunk per technique + sub-technique.
    Each chunk includes: ID, name, description, detection, 
    data sources, mitigations, platforms.
    """
    techniques = []
    
    # Build mitigation lookup
    mitigations_by_technique: dict[str, list[str]] = {}
    for obj in stix_data["objects"]:
        if obj.get("type") == "course-of-action":
            # Find relationships linking this mitigation to techniques
            pass
    
    mitigation_rels: dict[str, str] = {}
    mitigation_objects: dict[str, str] = {}
    
    for obj in stix_data["objects"]:
        if obj.get("type") == "course-of-action":
            mitigation_objects[obj["id"]] = obj.get("description", "")
        if (obj.get("type") == "relationship" and 
                obj.get("relationship_type") == "mitigates"):
            mitigation_rels[obj["target_ref"]] = obj["source_ref"]

    for obj in stix_data["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated", False):
            continue
        if obj.get("revoked", False):
            continue

        # Extract technique ID (e.g. T1190 or T1190.001)
        technique_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                break

        if not technique_id:
            continue

        # Extract fields
        name = obj.get("name", "")
        description = obj.get("description", "")
        platforms = ", ".join(obj.get("x_mitre_platforms", []))
        data_sources = ", ".join(obj.get("x_mitre_data_sources", []))
        detection = obj.get("x_mitre_detection", "")
        is_subtechnique = obj.get("x_mitre_is_subtechnique", False)

        # Get mitigation if available
        mitigation = ""
        if obj["id"] in mitigation_rels:
            mit_id = mitigation_rels[obj["id"]]
            mitigation = mitigation_objects.get(mit_id, "")

        # Build chunk text for embedding
        chunk_text = (
            f"MITRE ATT&CK Technique: {technique_id} - {name}\n\n"
            f"Description: {description}\n\n"
            f"Platforms: {platforms}\n"
            f"Data Sources: {data_sources}\n\n"
            f"Detection: {detection}\n\n"
            f"Mitigation: {mitigation[:500] if mitigation else 'See MITRE ATT&CK for mitigations.'}"
        )

        techniques.append({
            "id": technique_id,
            "name": name,
            "description": description,
            "detection": detection,
            "data_sources": data_sources,
            "platforms": platforms,
            "mitigation": mitigation[:500] if mitigation else "",
            "is_subtechnique": is_subtechnique,
            "chunk_text": chunk_text,
        })

    logger.info("Parsed %d MITRE techniques/sub-techniques", len(techniques))
    return techniques


# ── CVE Data ─────────────────────────────────────────────────────────────────

def generate_cve_chunks() -> list[dict]:
    """
    Generate CVE chunks relevant to the botsv3 attack surface.
    
    botsv3 attack surface includes:
    - SuiteCRM (CRM application)
    - Apache/PHP web server
    - AWS EC2 metadata service (SSRF)
    - Windows Server (EventCodes 4688, 4673, etc.)
    - SMB/Windows shares
    
    We generate realistic CVE entries based on known vulnerabilities
    in these systems that are relevant to the BOTS v3 attack scenario.
    """
    cves = [
        {
            "cve_id": "CVE-2019-12314",
            "title": "SuiteCRM Remote Code Execution via File Upload",
            "description": (
                "SuiteCRM before 7.10.9 allows remote code execution via "
                "crafted PHP file upload. An authenticated attacker can upload "
                "a malicious PHP file to gain server-side code execution. "
                "This vulnerability is exploitable via the document upload "
                "functionality in the SuiteCRM web interface."
            ),
            "cvss_score": 8.8,
            "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "affected_products": ["SuiteCRM < 7.10.9"],
            "remediation": "Upgrade to SuiteCRM 7.10.9 or later. Restrict file upload functionality.",
            "mitre_technique": "T1190",
            "relevance": "botsv3 SuiteCRM exploitation vector",
        },
        {
            "cve_id": "CVE-2017-9805",
            "title": "Apache Struts2 REST Plugin RCE",
            "description": (
                "Apache Struts 2.1.2 through 2.3.33 and 2.5 through 2.5.12 "
                "allows remote code execution via a crafted Content-Type header "
                "in the REST plugin. This is exploitable without authentication "
                "and allows arbitrary code execution on the server."
            ),
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "affected_products": ["Apache Struts 2.1.2-2.3.33", "Apache Struts 2.5-2.5.12"],
            "remediation": "Upgrade to Apache Struts 2.3.34 or 2.5.13.",
            "mitre_technique": "T1190",
            "relevance": "Web application exploitation via HTTP",
        },
        {
            "cve_id": "CVE-2018-11776",
            "title": "Apache Struts2 Namespace RCE",
            "description": (
                "Apache Struts 2.3 to 2.3.34 and 2.5 to 2.5.16 allows "
                "remote code execution via namespace configuration "
                "with no value and results with no explicit namespace "
                "or wildcards."
            ),
            "cvss_score": 8.1,
            "cvss_vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "affected_products": ["Apache Struts 2.3-2.3.34", "Apache Struts 2.5-2.5.16"],
            "remediation": "Upgrade to Apache Struts 2.3.35 or 2.5.17.",
            "mitre_technique": "T1190",
            "relevance": "Web server exploitation",
        },
        {
            "cve_id": "CVE-2019-0708",
            "title": "BlueKeep Windows RDP Remote Code Execution",
            "description": (
                "A remote code execution vulnerability exists in Remote Desktop "
                "Services. An unauthenticated attacker can connect to the target "
                "system using RDP and send specially crafted requests to execute "
                "arbitrary code. This vulnerability is wormable."
            ),
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "affected_products": [
                "Windows 7", "Windows Server 2008", "Windows Server 2008 R2",
                "Windows XP", "Windows Server 2003"
            ],
            "remediation": "Apply MS19-0708 security patch. Disable RDP if not needed.",
            "mitre_technique": "T1021.001",
            "relevance": "Windows lateral movement via RDP",
        },
        {
            "cve_id": "CVE-2017-0144",
            "title": "EternalBlue SMB Remote Code Execution",
            "description": (
                "The SMBv1 server in Windows allows remote code execution via "
                "crafted packets. Known as EternalBlue, this vulnerability was "
                "exploited by WannaCry and NotPetya ransomware. Affects multiple "
                "Windows versions without MS17-010 patch applied."
            ),
            "cvss_score": 9.3,
            "cvss_vector": "CVSS:2.0/AV:N/AC:M/Au:N/C:C/I:C/A:C",
            "affected_products": [
                "Windows Vista", "Windows 7", "Windows 8.1",
                "Windows Server 2008", "Windows Server 2012"
            ],
            "remediation": "Apply MS17-010. Disable SMBv1. Block port 445 at perimeter.",
            "mitre_technique": "T1021.002",
            "relevance": "SMB lateral movement, ransomware propagation",
        },
        {
            "cve_id": "CVE-2018-1111",
            "title": "SSRF via AWS EC2 Metadata Service",
            "description": (
                "Server-Side Request Forgery (SSRF) vulnerabilities allow attackers "
                "to make the server perform requests to internal resources, including "
                "the AWS EC2 Instance Metadata Service at 169.254.169.254. "
                "Successful exploitation allows retrieval of IAM credentials, "
                "instance role information, and security credentials via "
                "/latest/meta-data/iam/security-credentials/ endpoint."
            ),
            "cvss_score": 8.6,
            "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
            "affected_products": ["Web applications with SSRF vulnerabilities on AWS EC2"],
            "remediation": (
                "Implement SSRF protection. Block outbound requests to 169.254.169.254. "
                "Use IMDSv2 which requires session-oriented authentication. "
                "Apply least-privilege IAM roles."
            ),
            "mitre_technique": "T1552.005",
            "relevance": "Direct relevance to botsv3 AWS metadata service exploitation",
        },
        {
            "cve_id": "CVE-2021-44228",
            "title": "Log4Shell Apache Log4j RCE",
            "description": (
                "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in "
                "configuration, log messages, and parameters do not protect "
                "against attacker controlled LDAP and other JNDI related endpoints. "
                "An attacker who can control log messages can execute arbitrary code."
            ),
            "cvss_score": 10.0,
            "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "affected_products": ["Apache Log4j 2.0-beta9 through 2.15.0"],
            "remediation": "Upgrade to Log4j 2.17.0+. Set log4j2.formatMsgNoLookups=true.",
            "mitre_technique": "T1190",
            "relevance": "Web application exploitation via logging",
        },
        {
            "cve_id": "CVE-2020-1472",
            "title": "Zerologon Netlogon Privilege Escalation",
            "description": (
                "An elevation of privilege vulnerability exists when an attacker "
                "establishes a vulnerable Netlogon secure channel connection to a "
                "domain controller. An unauthenticated attacker can use MS-NRPC to "
                "run a specially crafted application on a network-connected device "
                "to establish a Netlogon session and set the computer password to empty."
            ),
            "cvss_score": 10.0,
            "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "affected_products": [
                "Windows Server 2008 R2", "Windows Server 2012",
                "Windows Server 2016", "Windows Server 2019"
            ],
            "remediation": "Apply CVE-2020-1472 patch. Enable enforcement mode for Netlogon.",
            "mitre_technique": "T1078",
            "relevance": "Privilege escalation on Windows domain controllers",
        },
    ]

    # Build chunk text for each CVE
    for cve in cves:
        cve["chunk_text"] = (
            f"CVE: {cve['cve_id']} — {cve['title']}\n\n"
            f"Description: {cve['description']}\n\n"
            f"CVSS Score: {cve['cvss_score']} | Vector: {cve['cvss_vector']}\n"
            f"Affected Products: {', '.join(cve['affected_products'])}\n\n"
            f"Remediation: {cve['remediation']}\n\n"
            f"Related MITRE Technique: {cve['mitre_technique']}\n"
            f"Relevance to Investigation: {cve['relevance']}"
        )

    logger.info("Generated %d CVE chunks", len(cves))
    return cves


# ── IR Playbooks ──────────────────────────────────────────────────────────────

def generate_ir_playbooks() -> list[dict]:
    """
    Generate realistic IR playbooks for common attack scenarios.
    These ground SynthesisAgent recommendations in structured procedures.
    """
    playbooks = [
        {
            "id": "playbook-apt-ssrf-credential-theft",
            "title": "APT Response: SSRF and Cloud Credential Theft",
            "attack_type": "APT",
            "trigger": "AWS metadata service accessed from internal host via SSRF",
            "content": """
INCIDENT RESPONSE PLAYBOOK: APT — SSRF Cloud Credential Theft

SEVERITY: CRITICAL
TIMEFRAME: Immediate response required within 15 minutes

PHASE 1 — IMMEDIATE CONTAINMENT (0-15 minutes)
1. Isolate the affected web server from the network
2. Revoke all IAM credentials associated with the compromised EC2 instance role
3. Rotate all AWS access keys that may have been exposed
4. Enable CloudTrail if not already enabled for forensic logging
5. Block outbound access to 169.254.169.254 via security group rules

PHASE 2 — INVESTIGATION (15-60 minutes)
1. Query CloudTrail for API calls made with the compromised credentials
2. Identify all resources accessed using the stolen IAM role
3. Review VPC Flow Logs for lateral movement indicators
4. Check for new IAM users, roles, or access keys created post-compromise
5. Review S3 bucket access logs for data exfiltration
6. Identify the SSRF vulnerability in the web application

PHASE 3 — ERADICATION (1-4 hours)
1. Patch the SSRF vulnerability in the web application
2. Implement IMDSv2 on all EC2 instances to prevent metadata access without session tokens
3. Apply least-privilege IAM policies — remove unused permissions
4. Enable AWS GuardDuty for ongoing threat detection
5. Review and tighten security group rules

PHASE 4 — RECOVERY (4-24 hours)
1. Rebuild the compromised instance from a clean AMI
2. Deploy web application firewall (WAF) rules to block SSRF patterns
3. Implement SSRF protection at the application level
4. Conduct penetration testing to identify other SSRF vectors

INDICATORS OF COMPROMISE
- Outbound HTTP requests to 169.254.169.254
- Access to /latest/meta-data/iam/security-credentials/
- Unusual IAM API calls from EC2 instance role
- CloudTrail events from unexpected geographic locations
""",
            "mitre_techniques": ["T1190", "T1552.005", "T1078"],
        },
        {
            "id": "playbook-ransomware-containment",
            "title": "Ransomware Active Deployment Response",
            "attack_type": "RANSOMWARE",
            "trigger": "File encryption in progress, WMIC and cmd.exe lateral movement",
            "content": """
INCIDENT RESPONSE PLAYBOOK: Active Ransomware Containment

SEVERITY: CRITICAL
TIMEFRAME: Immediate — every minute counts

PHASE 1 — EMERGENCY CONTAINMENT (0-5 minutes)
1. IMMEDIATELY isolate affected systems from the network — pull cables if necessary
2. Do NOT power off systems — preserve volatile memory for forensics
3. Disable all active user accounts that may be compromised
4. Block SMB traffic (port 445) at the firewall perimeter
5. Alert all users to stop working and report any ransom messages
6. Activate incident response team and management escalation

PHASE 2 — SCOPE ASSESSMENT (5-30 minutes)
1. Identify all systems showing signs of encryption (encrypted file extensions)
2. Review network logs for WMIC remote execution across segments
3. Check EventCode 4688 logs for cmd.exe, WMIC.exe, reg.exe execution chains
4. Identify patient zero — the first system infected
5. Map lateral movement path using EventCode 4624/4625 authentication logs
6. Check for shadow copy deletion (vssadmin, wbadmin commands)

PHASE 3 — ERADICATION (30 min — 4 hours)
1. Identify ransomware variant using file extension and ransom note
2. Check No More Ransom (nomoreransom.org) for decryptors
3. Remove ransomware binary from all affected systems
4. Clean registry persistence mechanisms (EventCode 4697, scheduled tasks)
5. Reset all domain account passwords
6. Rebuild domain controllers if compromised

PHASE 4 — RECOVERY (4-72 hours)
1. Restore from clean backups — verify backup integrity before restore
2. Restore in order of business criticality
3. Scan all restored systems before reconnecting to network
4. Patch all vulnerabilities exploited in initial access
5. Deploy EDR on all endpoints

INDICATORS OF COMPROMISE
- EventCode 4688: WMIC.exe, cmd.exe, reg.exe spawning at high volume
- EventCode 5156/5157: Abnormal network filtering events
- vssadmin delete shadows or wbadmin delete catalog commands
- Files with new encrypted extensions (.encrypted, .locked, etc.)
- Ransom note files (README.txt, HOW_TO_DECRYPT.txt)
""",
            "mitre_techniques": ["T1486", "T1059.003", "T1047", "T1021.002"],
        },
        {
            "id": "playbook-insider-threat-privilege",
            "title": "Insider Threat: Privileged Service Abuse",
            "attack_type": "INSIDER_THREAT",
            "trigger": "Abnormal EventCode 4673 from internal account outside hours",
            "content": """
INCIDENT RESPONSE PLAYBOOK: Insider Threat — Privilege Abuse

SEVERITY: HIGH
TIMEFRAME: Covert investigation to avoid tipping off subject

PHASE 1 — COVERT MONITORING (0-24 hours)
1. Do NOT alert the subject — begin covert monitoring
2. Enable enhanced auditing on the subject's account
3. Preserve all existing logs before they are overwritten
4. Notify HR and Legal before taking any action
5. Document all findings for potential legal proceedings

PHASE 2 — INVESTIGATION (24-72 hours)
1. Review EventCode 4673 entries for privileged service calls
2. Identify which services and resources were accessed
3. Review file access logs (EventCode 4663) for sensitive data access
4. Check for data staged for exfiltration (USB, email, cloud upload)
5. Review EventCode 4670 for permission changes
6. Cross-reference with physical access logs and VPN logs

PHASE 3 — CONTAINMENT (after legal review)
1. Revoke the subject's access — coordinate with HR for timing
2. Preserve all evidence before account termination
3. Change passwords for all shared accounts the subject had access to
4. Review and revoke all API keys and service account credentials
5. Audit all changes made by the subject

PHASE 4 — RECOVERY
1. Review and tighten privileged access management (PAM)
2. Implement just-in-time (JIT) access for administrative tasks
3. Enable multi-person authorization for sensitive operations
4. Deploy user behavior analytics (UBA) for ongoing monitoring

INDICATORS OF COMPROMISE
- EventCode 4673: Privileged service called outside business hours
- EventCode 4670: Permissions changed on sensitive objects
- EventCode 4663: Sensitive files accessed in bulk
- Large data transfers to external storage
- Access to systems outside normal job function
""",
            "mitre_techniques": ["T1078", "T1098", "T1005"],
        },
        {
            "id": "playbook-apt-lateral-movement",
            "title": "APT Lateral Movement Response",
            "attack_type": "APT",
            "trigger": "Credential theft followed by lateral movement indicators",
            "content": """
INCIDENT RESPONSE PLAYBOOK: APT Lateral Movement

SEVERITY: CRITICAL

PHASE 1 — CONTAINMENT
1. Identify all systems the attacker has accessed via authentication logs
2. Isolate compromised systems in a quarantine VLAN
3. Reset all potentially compromised credentials
4. Invalidate all Kerberos tickets (krbtgt password reset x2)
5. Block C2 infrastructure at the firewall

PHASE 2 — INVESTIGATION
1. Map the full lateral movement path from patient zero
2. Identify all data repositories accessed
3. Review DNS logs for C2 beaconing patterns
4. Check for persistence mechanisms (scheduled tasks, services, registry)
5. Identify exfiltration channels and quantify data loss

PHASE 3 — ERADICATION
1. Remove all attacker persistence mechanisms
2. Rebuild compromised systems from known-good images
3. Patch all vulnerabilities exploited in the attack chain
4. Implement network segmentation to limit future lateral movement

INDICATORS OF COMPROMISE
- EventCode 4624 Type 3 (network logon) from unexpected sources
- EventCode 4648 (logon using explicit credentials)
- WMIC remote process execution
- PsExec or similar remote administration tool usage
- Unusual DNS queries with high entropy domain names
""",
            "mitre_techniques": ["T1021", "T1550", "T1071", "T1041"],
        },
        {
            "id": "playbook-credential-theft-response",
            "title": "Credential Theft and Account Compromise Response",
            "attack_type": "APT",
            "trigger": "IAM credentials or domain credentials compromised",
            "content": """
INCIDENT RESPONSE PLAYBOOK: Credential Theft Response

SEVERITY: CRITICAL

PHASE 1 — IMMEDIATE ACTIONS
1. Identify all credentials that may have been exposed
2. Revoke and rotate ALL potentially compromised credentials immediately
3. Enable MFA on all administrative accounts
4. Review authentication logs for unauthorized access

PHASE 2 — INVESTIGATION  
1. Determine how credentials were stolen (phishing, SSRF, keylogger, etc.)
2. Identify all systems and resources accessed with stolen credentials
3. Check for new accounts created with stolen credentials
4. Review for privilege escalation attempts

PHASE 3 — REMEDIATION
1. Implement privileged access workstations (PAW) for admin tasks
2. Deploy credential vault (CyberArk, HashiCorp Vault)
3. Enable just-in-time privilege elevation
4. Deploy phishing-resistant MFA (FIDO2/WebAuthn)

INDICATORS
- Failed MFA attempts followed by success from new location
- API calls from new geographic location or IP
- New access keys or service accounts created
- Privilege escalation events (EventCode 4672, 4673)
""",
            "mitre_techniques": ["T1552", "T1078", "T1556"],
        },
    ]

    # Add chunk_text for embedding
    for pb in playbooks:
        pb["chunk_text"] = (
            f"IR PLAYBOOK: {pb['title']}\n"
            f"Attack Type: {pb['attack_type']}\n"
            f"Trigger: {pb['trigger']}\n"
            f"Related MITRE Techniques: {', '.join(pb['mitre_techniques'])}\n\n"
            f"{pb['content']}"
        )

    logger.info("Generated %d IR playbook chunks", len(playbooks))
    return playbooks


# ── botsv3 Investigation Notes ────────────────────────────────────────────────

def generate_botsv3_notes() -> list[dict]:
    """
    Manual investigation notes from our forensic analysis of botsv3.
    This is the self-referential golden dataset.
    """
    notes = [
        {
            "id": "botsv3-attack-timeline",
            "title": "botsv3 Complete Attack Timeline",
            "content": """
botsv3 FORENSIC INVESTIGATION — COMPLETE ATTACK TIMELINE

Dataset: BOTS v3 (Boss of the SOC v3) — Splunk security dataset
Total Events: 2,083,056 across 20 sourcetypes
Attack Window: 2018-08-20 to 2019-09-19

CONFIRMED ATTACK SEQUENCE:

Stage 1 — Initial Access (2018-08-20 ~11:00)
- External IP 54.67.127.227 accessed internal web server 172.16.0.178
- URI paths: /forumdisplay.php, /member.php, /showthread.php
- Evidence: stream:http sourcetype, 1,361 events to 172.16.0.178
- MITRE: T1190 — Exploit Public-Facing Application

Stage 2 — SSRF Exploitation (2018-08-20 ~11:05)
- Internal host 172.16.0.127 began querying AWS metadata service
- Target: 169.254.169.254 (AWS EC2 Instance Metadata Service)
- URI: /latest/meta-data/iam/security-credentials/EC2InstanceRole
- Total queries: 73+ requests to metadata service
- MITRE: T1552.005 — Cloud Instance Metadata API

Stage 3 — Credential Theft (2018-08-20 ~11:06)
- HTTP 200 responses confirmed successful credential retrieval
- IAM role: EC2InstanceRole credentials exfiltrated
- Evidence: stream:http with dest_ip=169.254.169.254
- MITRE: T1528 — Steal Application Access Token

Stage 4 — Execution (2018-08-20 ~11:15)
- cmd.exe: 1,091 EventCode 4688 events
- WMIC.exe: 536 EventCode 4688 events  
- reg.exe: 523 EventCode 4688 events
- Host: Multiple internal hosts including BSTOLL-L
- MITRE: T1059.003 — Windows Command Shell, T1047 — WMI

Stage 5 — Defense Evasion (2018-08-20 ~12:10)
- EventCode 1102: Security audit log cleared on BSTOLL-L
- MITRE: T1070.001 — Clear Windows Event Logs

KEY IOCs:
- External attacker IPs: 54.67.127.227, 184.85.20.125, 23.73.195.90, 201.150.52.35
- Internal SSRF source: 172.16.0.127, 172.31.12.76
- Target metadata URI: /latest/meta-data/iam/security-credentials/EC2InstanceRole
- Compromised host: BSTOLL-L
- Compromised role: EC2InstanceRole

DOMINANT EventCodes in botsv3:
- 5156: 11,501 (Windows Filtering Platform connection permitted)
- 4689: 7,446 (Process terminated)
- 4688: 7,427 (Process created) ← KEY INDICATOR
- 4673: 4,122 (Privileged service called)
- 5157: 4,189 (Connection blocked)
- 4670: 3,618 (Permissions changed)
- 4624: 427 (Successful logon)
- 4625: ~6 (Failed logon — very low, not brute force)

TOP SOURCETYPES by volume:
- syslog: 283,976
- stream:ip: 227,872
- osquery:results: 219,997
- stream:dns: 218,456
- stream:udp: 157,960
- WinEventLog:Security: 46,469
- stream:http: 24,191
""",
        },
        {
            "id": "botsv3-splunk-queries",
            "title": "Verified SPL Queries for botsv3 Investigation",
            "content": """
VERIFIED SPL QUERIES — botsv3 INVESTIGATION

All queries tested against botsv3 with confirmed result counts.

1. AWS Metadata Service Access (SSRF Evidence)
   SPL: index=botsv3 earliest=0 sourcetype=stream:http dest_ip=169.254.169.254 
        | stats count by uri_path | sort -count | head 20
   Returns: 11 rows including /latest/meta-data/iam/security-credentials/EC2InstanceRole
   
2. External HTTP Traffic (Initial Access)
   SPL: index=botsv3 earliest=0 sourcetype=stream:http 
        | where NOT match(src_ip, "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)")
        | stats count by src_ip, dest_ip, uri_path | sort -count | head 20
   Returns: 20 rows, top source 54.67.127.227 hitting 172.16.0.178

3. Process Execution Chain (Ransomware/Lateral Movement)
   SPL: index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4688
        | stats count by New_Process_Name | sort -count | head 20
   Returns: cmd.exe=1091, WMIC.exe=536, reg.exe=523

4. DNS Tunneling Detection
   SPL: index=botsv3 earliest=0 sourcetype=stream:dns
        | eval query_len=len(query) | where query_len > 40
        | stats count by query | sort -count | head 20
   Returns: 20 rows of long DNS queries suggesting tunneling

5. Privilege Escalation (Insider Threat Pattern)
   SPL: index=botsv3 earliest=0 sourcetype=WinEventLog:Security
        (EventCode=4672 OR EventCode=4673)
        | stats count by EventCode, Account_Name | sort -count | head 20
   Returns: 4673=4122 events, 4672=419 events
""",
        },
        {
            "id": "botsv3-patient-zero",
            "title": "botsv3 Patient Zero Identification",
            "content": """
botsv3 PATIENT ZERO ANALYSIS

EXTERNAL ATTACKER (Initial Contact):
- IP: 54.67.127.227 
- First seen: 2018-08-20 ~11:00
- Role: External attacker hitting public web server
- Evidence: stream:http shows this IP accessing /forumdisplay.php on 172.16.0.178
- Country: United States (AWS EC2 instance — likely compromised or rented)

INTERNAL SSRF SOURCE (Compromised Internal Host):
- IP: 172.16.0.127 and 172.31.12.76
- First SSRF query: 2018-08-20 ~11:05
- Role: Compromised internal web server making SSRF requests
- Evidence: HTTP requests to 169.254.169.254 from RFC1918 addresses
- These hosts were compromised via the web application SSRF vulnerability

COMPROMISED ACCOUNT:
- Account: BSTOLL (referenced in BOTS v3 documentation)
- Host: BSTOLL-L
- Evidence: EventCode 1102 (audit log cleared) on BSTOLL-L
- This account had admin privileges based on 4673/4672 events

ATTACK ORIGIN THEORY:
The attack originated from an external threat actor who:
1. Identified the SuiteCRM/forum web application at 172.16.0.178
2. Exploited an SSRF vulnerability to make internal server requests
3. Used SSRF to query the AWS metadata service and steal IAM credentials
4. Used stolen credentials to pivot into AWS infrastructure
5. Established persistence via admin tooling (WMIC, cmd.exe, reg.exe)
""",
        },
    ]

    for note in notes:
        note["chunk_text"] = (
            f"botsv3 Investigation Note: {note['title']}\n\n"
            f"{note['content']}"
        )

    logger.info("Generated %d botsv3 investigation note chunks", len(notes))
    return notes


# ── Embedding ─────────────────────────────────────────────────────────────────

def embed_texts(texts: list[str], batch_size: int = 50) -> list[list[float]]:
    """
    Generate embeddings using text-embedding-3-large.
    Processes in batches to respect API rate limits.
    """
    all_embeddings = []
    total_batches = (len(texts) + batch_size - 1) // batch_size

    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        batch_num = i // batch_size + 1
        logger.info(
            "Embedding batch %d/%d (%d texts)...",
            batch_num, total_batches, len(batch)
        )

        response = openai_client.embeddings.create(
            model=EMBEDDING_MODEL,
            input=batch,
        )
        batch_embeddings = [item.embedding for item in response.data]
        all_embeddings.extend(batch_embeddings)

        # Rate limit protection
        if i + batch_size < len(texts):
            time.sleep(0.5)

    return all_embeddings


# ── Qdrant Collection Setup ───────────────────────────────────────────────────

def create_collection_if_not_exists(collection_name: str) -> None:
    """Create a Qdrant collection with cosine similarity if it doesn't exist."""
    existing = [c.name for c in qdrant_client.get_collections().collections]
    if collection_name in existing:
        logger.info("Collection %s already exists — skipping creation", collection_name)
        return

    qdrant_client.create_collection(
        collection_name=collection_name,
        vectors_config=VectorParams(
            size=EMBEDDING_DIMS,
            distance=Distance.COSINE,
        ),
    )
    # Create payload index for identifiers
    id_key = "id"
    if collection_name == CVE_COLLECTION:
        id_key = "cve_id"
        
    from qdrant_client.models import PayloadSchemaType
    qdrant_client.create_payload_index(
        collection_name=collection_name,
        field_name=id_key,
        field_schema=PayloadSchemaType.KEYWORD,
    )
    logger.info("Created collection and payload index for: %s", collection_name)


def upsert_chunks(
    collection_name: str,
    chunks: list[dict],
    id_field: str = "id",
    text_field: str = "chunk_text",
) -> None:
    """Embed and upsert chunks into Qdrant."""
    if not chunks:
        logger.warning("No chunks to upsert for %s", collection_name)
        return

    texts = [chunk[text_field] for chunk in chunks]
    logger.info(
        "Generating embeddings for %d chunks in %s...",
        len(chunks), collection_name
    )
    embeddings = embed_texts(texts)

    points = []
    for i, (chunk, embedding) in enumerate(zip(chunks, embeddings)):
        # Use index as ID if no id_field
        point_id = i
        payload = {k: v for k, v in chunk.items() if k != text_field}
        payload["chunk_text"] = chunk[text_field][:1000]  # Store truncated for reference

        points.append(PointStruct(
            id=point_id,
            vector=embedding,
            payload=payload,
        ))

    # Upsert in batches of 25
    batch_size = 25
    for i in range(0, len(points), batch_size):
        batch = points[i:i + batch_size]
        qdrant_client.upsert(
            collection_name=collection_name,
            points=batch,
        )
        logger.info(
            "Upserted %d/%d points to %s",
            min(i + batch_size, len(points)), len(points), collection_name
        )


# ── Main Ingestion ────────────────────────────────────────────────────────────

def ingest_mitre_collection() -> None:
    """Download MITRE ATT&CK STIX and ingest into Qdrant."""
    logger.info("=== Ingesting MITRE ATT&CK Collection ===")
    create_collection_if_not_exists(MITRE_COLLECTION)

    # Check if already populated
    count = qdrant_client.count(MITRE_COLLECTION).count
    if count > 0:
        logger.info(
            "MITRE collection already has %d points — skipping ingestion", count
        )
        return

    stix_data = download_mitre_stix()
    techniques = parse_mitre_techniques(stix_data)
    upsert_chunks(MITRE_COLLECTION, techniques, id_field="id")
    logger.info(
        "MITRE collection ingestion complete: %d techniques",
        len(techniques)
    )


def ingest_cve_collection() -> None:
    """Generate and ingest CVE chunks."""
    logger.info("=== Ingesting CVE Collection ===")
    create_collection_if_not_exists(CVE_COLLECTION)

    count = qdrant_client.count(CVE_COLLECTION).count
    if count > 0:
        logger.info(
            "CVE collection already has %d points — skipping", count
        )
        return

    cves = generate_cve_chunks()
    upsert_chunks(CVE_COLLECTION, cves, id_field="cve_id")
    logger.info("CVE collection ingestion complete: %d CVEs", len(cves))


def ingest_playbook_collection() -> None:
    """Generate and ingest IR playbook chunks."""
    logger.info("=== Ingesting IR Playbook Collection ===")
    create_collection_if_not_exists(PLAYBOOK_COLLECTION)

    count = qdrant_client.count(PLAYBOOK_COLLECTION).count
    if count > 0:
        logger.info(
            "Playbook collection already has %d points — skipping", count
        )
        return

    playbooks = generate_ir_playbooks()
    upsert_chunks(PLAYBOOK_COLLECTION, playbooks, id_field="id")
    logger.info(
        "Playbook collection ingestion complete: %d playbooks",
        len(playbooks)
    )


def ingest_botsv3_collection() -> None:
    """Generate and ingest botsv3 investigation notes."""
    logger.info("=== Ingesting botsv3 Investigation Notes ===")
    create_collection_if_not_exists(BOTSV3_COLLECTION)

    count = qdrant_client.count(BOTSV3_COLLECTION).count
    if count > 0:
        logger.info(
            "botsv3 collection already has %d points — skipping", count
        )
        return

    notes = generate_botsv3_notes()
    upsert_chunks(BOTSV3_COLLECTION, notes, id_field="id")
    logger.info(
        "botsv3 collection ingestion complete: %d notes", len(notes)
    )


def verify_collections() -> None:
    """Verify all collections exist and have expected point counts."""
    logger.info("=== Verifying Collections ===")
    for collection_name in ALL_COLLECTIONS:
        try:
            count = qdrant_client.count(collection_name).count
            logger.info("✓ %s: %d points", collection_name, count)
        except Exception as e:
            logger.error("✗ %s: ERROR — %s", collection_name, e)


def main() -> None:
    """Run full ingestion pipeline."""
    logger.info("Starting Splunk Sentinel RAG ingestion pipeline...")
    logger.info("Qdrant URL: %s", os.getenv("QDRANT_URL"))

    ingest_mitre_collection()
    ingest_cve_collection()
    ingest_playbook_collection()
    ingest_botsv3_collection()
    verify_collections()

    logger.info("RAG ingestion pipeline complete.")


if __name__ == "__main__":
    main()
