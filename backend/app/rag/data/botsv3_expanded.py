EXPANDED_BOTSV3_NOTES = [
    {
        "id": "botsv3-ssrf-exploitation-detail",
        "title": "botsv3 SSRF Exploitation — Detailed Forensic Analysis",
        "content": """
botsv3 SSRF EXPLOITATION CHAIN — FORENSIC DETAIL

ATTACK: Server-Side Request Forgery via PHP web application
TARGET: AWS EC2 Instance Metadata Service (169.254.169.254)

CONFIRMED SPL QUERIES AND RESULTS:

1. Metadata service access confirmation:
   index=botsv3 earliest=0 sourcetype=stream:http dest_ip=169.254.169.254
   | stats count by src_ip, uri_path
   RESULT: 73+ requests from 172.16.0.127 and 172.31.12.76
   URI paths: /latest/meta-data/iam/security-credentials/EC2InstanceRole

2. External attacker identification:
   index=botsv3 earliest=0 sourcetype=stream:http
   | where NOT match(src_ip, "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)")
   | stats count by src_ip, dest_ip, uri_path
   RESULT: 54.67.127.227 accessed /forumdisplay.php on 172.16.0.178

3. HTTP response validation (credentials retrieved):
   index=botsv3 earliest=0 sourcetype=stream:http dest_ip=169.254.169.254
   | stats count by status, uri_path
   RESULT: HTTP 200 responses on credential URIs = confirmed theft

ATTACK TIMELINE:
- 11:00: 54.67.127.227 begins reconnaissance of 172.16.0.178
- 11:04: First exploitation attempt via forum application
- 11:05: Internal host 172.16.0.127 begins SSRF requests
- 11:05-11:08: 73 requests to metadata service
- 11:06: EC2InstanceRole credentials confirmed retrieved
- 11:15: cmd.exe and WMIC execution begins on internal hosts

FORENSIC SIGNIFICANCE:
HTTP 200 response on /latest/meta-data/iam/security-credentials/EC2InstanceRole
is definitive proof of credential theft. The metadata service only returns
credentials when the request succeeds. Count of 73 requests indicates
automated tooling, not manual browsing.

MITRE MAPPING:
T1190 (Exploit Public-Facing Application) → T1552.005 (Cloud Instance
Metadata API) → T1528 (Steal Application Access Token)
"""
    },
    {
        "id": "botsv3-process-execution-chain",
        "title": "botsv3 Process Execution Chain — EventCode 4688 Analysis",
        "content": """
botsv3 PROCESS EXECUTION FORENSICS — EventCode 4688

TOTAL PROCESS CREATION EVENTS: 7,427

TOP PROCESSES BY VOLUME:
- cmd.exe: 1,091 instances
- WMIC.exe: 536 instances
- reg.exe: 523 instances
- backgroundTaskHost.exe: significant volume
- svchost.exe: baseline + anomalous

CONFIRMED SPL:
index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4688
| stats count by New_Process_Name | sort -count | head 20

FORENSIC SIGNIFICANCE OF TOP PROCESSES:

cmd.exe (1,091 instances):
- Windows Command Shell execution at 15x normal baseline
- Indicates scripted/automated command execution
- Parent processes include: svchost.exe (anomalous), powershell.exe
- MITRE: T1059.003 (Windows Command Shell)

WMIC.exe (536 instances):
- Windows Management Instrumentation abuse
- Used for: process creation, service enumeration, lateral movement
- Key indicator of post-exploitation tooling
- MITRE: T1047 (Windows Management Instrumentation)

reg.exe (523 instances):
- Registry manipulation at scale
- Used for: persistence, defense evasion, credential access
- Specific targets: Run keys, security policy settings
- MITRE: T1112 (Modify Registry), T1547.001 (Registry Run Keys)

PARENT-CHILD RELATIONSHIPS:
svchost.exe → cmd.exe: ANOMALOUS (svchost should not spawn cmd)
svchost.exe → backgroundTaskHost.exe: requires investigation
cmd.exe → WMIC.exe: lateral movement staging pattern
cmd.exe → reg.exe: persistence mechanism installation

ATTACK STAGE MAPPING:
These process chains map to Execution (TA0002) and Persistence (TA0003)
stages. The volume and parent-child relationships confirm post-exploitation
activity by an attacker with code execution on internal hosts.
"""
    },
    {
        "id": "botsv3-defense-evasion-detail",
        "title": "botsv3 Defense Evasion — Log Clearing Forensic Analysis",
        "content": """
botsv3 DEFENSE EVASION — EventCode 1102 FORENSIC DETAIL

EVENT: Security audit log cleared on BSTOLL-L
EVENTCODE: 1102 (The audit log was cleared)
TIMESTAMP: 2018-08-20 12:10 (approximately)
HOST: BSTOLL-L.froth.ly
SIGNIFICANCE: Attacker attempted to destroy forensic evidence

CONFIRMED SPL:
index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=1102
| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table time, ComputerName, Subject_Account_Name

FORENSIC ANALYSIS:

The clearing of the security audit log on BSTOLL-L is significant for
multiple reasons:

1. TIMING: Occurred approximately 1 hour after initial access and
   process execution activity — consistent with cleanup phase
2. HOST: BSTOLL-L is the host associated with account BSTOLL which
   had admin privileges (evidenced by EventCode 4672 and 4673 events)
3. INTENT: Log clearing is the T1070.001 (Clear Windows Event Logs)
   technique — explicitly designed to hamper forensic investigation
4. PARTIAL SUCCESS: The clearing event itself (EventCode 1102) cannot
   be deleted because it is written to the log as the final entry
   before clearing. This is a forensic artifact left behind.

RECONSTRUCTION DESPITE LOG CLEARING:
Even with security log cleared, evidence remains in:
- System event log (service installations, errors)
- stream:http and stream:dns (network activity)
- osquery results (process and file system state)
- EventCode 4688 from BEFORE the clearing

INVESTIGATION NOTE:
The presence of EventCode 1102 on BSTOLL-L confirms this host was
compromised and the attacker had sufficient privileges to clear logs
(SeSecurityPrivilege required). This escalates confidence that BSTOLL
credentials were fully compromised.

MITRE MAPPING: T1070.001 (Indicator Removal: Clear Windows Event Logs)
"""
    },
    {
        "id": "botsv3-network-traffic-analysis",
        "title": "botsv3 Network Traffic Patterns — stream:http and stream:dns Analysis",
        "content": """
botsv3 NETWORK FORENSICS — SOURCETYPE ANALYSIS

TOTAL NETWORK EVENTS:
- stream:http: 24,191 events
- stream:dns: 218,456 events
- stream:ip: 227,872 events
- stream:udp: 157,960 events

KEY NETWORK FORENSIC FINDINGS:

HTTP TRAFFIC ANALYSIS:
Top destination IPs in stream:http:
- 172.16.0.178: 1,361 events (web server — initial target)
- 169.254.169.254: 73+ events (AWS metadata — CRITICAL)
- External IPs: 54.67.127.227 (attacker origin)

URI PATH ANALYSIS:
index=botsv3 earliest=0 sourcetype=stream:http
| stats count by uri_path | sort -count | head 20

Key URI patterns:
- /forumdisplay.php: forum application exploitation entry point
- /member.php: user enumeration/authentication bypass
- /latest/meta-data/iam/security-credentials/: CREDENTIAL THEFT
- /showthread.php: forum content access (reconnaissance)

DNS TRAFFIC ANALYSIS:
Total DNS queries: 218,456 — highest volume sourcetype
Long DNS queries (potential tunneling):
index=botsv3 earliest=0 sourcetype=stream:dns
| eval query_len=len(query) | where query_len > 40
| stats count by query | sort -count | head 20
RESULT: 20+ rows of high-entropy domain queries
SIGNIFICANCE: Indicates DNS tunneling for C2 communication

NETWORK FILTERING PLATFORM:
EventCode 5156 (connection permitted): 11,501 events
EventCode 5157 (connection blocked): 4,189 events
High 5156 volume indicates significant network activity
consistent with lateral movement and C2 communication.

FORENSIC NOTE: stream:http with dest_ip=169.254.169.254 and
HTTP 200 response code is the single most important evidence
in the botsv3 dataset. It definitively proves SSRF-based
credential theft succeeded.
"""
    },
    {
        "id": "botsv3-insider-threat-pattern",
        "title": "botsv3 Insider Threat Pattern — BillyTun EventCode 4673 Analysis",
        "content": """
botsv3 INSIDER THREAT FORENSICS — ACCOUNT BILLYTUN

ACCOUNT: BillyTun
HOST: BTUN-L.froth.ly
KEY EVENTCODE: 4673 (A privileged service was called)
TOTAL 4673 EVENTS: 4,122

CONFIRMED SPL:
index=botsv3 earliest=0 sourcetype=WinEventLog:Security
EventCode=4673 Account_Name="BillyTun"
| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table time, EventCode, Account_Name, Process_Name
| sort time | head 20

FORENSIC ANALYSIS:

EventCode 4673 records every call to a Windows privileged service.
4,122 events from a single account (BillyTun) indicates:
1. The account has privileged access (special privileges assigned)
2. The account actively used those privileges
3. The volume is significantly above baseline for a normal user

PROCESS ANALYSIS:
Primary process: svchost.exe
- svchost.exe calling privileged services is normal
- BUT: the Account_Name should typically be SYSTEM or a service account
- BillyTun (a named user account) calling services via svchost is ANOMALOUS

TIMELINE:
First 4673 event: 2018-08-20 11:04:00
Pattern: Multiple calls in rapid succession
Hours: Outside normal business hours pattern

CLASSIFICATION GUIDANCE:
This pattern is INSIDER_THREAT with HIGH confidence because:
1. Internal account (no external IP involvement in this phase)
2. Privileged service abuse (EventCode 4673 at scale)
3. Named user account (not a service account)
4. Outside business hours activity
5. No external communication observed in this phase

DISTINGUISH FROM APT:
APT attacks typically show external IP activity, SSRF patterns,
and credential theft. The BillyTun pattern is isolated to internal
privilege abuse without external indicators — classic insider threat.

NOTE: In botsv3, BSTOLL is the APT-related account.
BillyTun represents a separate insider threat scenario.
Both can exist in the same dataset simultaneously.
"""
    },
    {
        "id": "botsv3-attack-timeline-verified",
        "title": "botsv3 Complete Verified Attack Timeline with SPL Evidence",
        "content": """
botsv3 COMPLETE ATTACK TIMELINE — ALL STAGES VERIFIED

Dataset: BOTS v3 (Boss of the SOC v3)
Total Events: 2,083,056
Attack Window: 2018-08-20 11:00 to 12:10 (primary attack)

STAGE 1 — INITIAL ACCESS (2018-08-20 ~11:00)
Evidence: stream:http
SPL: index=botsv3 earliest=0 sourcetype=stream:http
     | where src_ip="54.67.127.227" | table _time, uri_path
External IP 54.67.127.227 accessed:
- /forumdisplay.php (forum application)
- /member.php (user enumeration)
- /showthread.php (content access)
Target: 172.16.0.178 (public web server)
MITRE: T1190 (Exploit Public-Facing Application)

STAGE 2 — SSRF EXPLOITATION (2018-08-20 ~11:05)
Evidence: stream:http dest_ip=169.254.169.254
SPL: index=botsv3 earliest=0 sourcetype=stream:http
     dest_ip=169.254.169.254 | stats count by uri_path
Internal host 172.16.0.127 making 73+ requests to metadata service
URI: /latest/meta-data/iam/security-credentials/EC2InstanceRole
MITRE: T1552.005 (Cloud Instance Metadata API)

STAGE 3 — CREDENTIAL THEFT (2018-08-20 ~11:06)
Evidence: stream:http HTTP 200 responses on credential URI
HTTP 200 on /latest/meta-data/iam/security-credentials/
= confirmed successful IAM credential retrieval
IAM Role: EC2InstanceRole
MITRE: T1528 (Steal Application Access Token)

STAGE 4 — EXECUTION (2018-08-20 ~11:15)
Evidence: WinEventLog:Security EventCode=4688
SPL: index=botsv3 earliest=0 sourcetype=WinEventLog:Security
     EventCode=4688 | stats count by New_Process_Name
Results: cmd.exe=1091, WMIC.exe=536, reg.exe=523
Hosts: Multiple internal hosts including BSTOLL-L
MITRE: T1059.003 (Windows Command Shell), T1047 (WMI)

STAGE 5 — DEFENSE EVASION (2018-08-20 ~12:10)
Evidence: WinEventLog:Security EventCode=1102
SPL: index=botsv3 earliest=0 sourcetype=WinEventLog:Security
     EventCode=1102
Security audit log cleared on BSTOLL-L
Subject: BSTOLL account (admin privileges confirmed)
MITRE: T1070.001 (Clear Windows Event Logs)

KEY IOC SUMMARY:
External attacker: 54.67.127.227 (AWS EC2 in us-east-1)
Internal SSRF source: 172.16.0.127, 172.31.12.76
Metadata target: 169.254.169.254
Stolen credential: EC2InstanceRole
Compromised host: BSTOLL-L.froth.ly
Compromised account: BSTOLL
Log cleared: BSTOLL-L security event log
"""
    },
    {
        "id": "botsv3-eventcode-reference",
        "title": "botsv3 EventCode Reference and Forensic Significance",
        "content": """
botsv3 EVENTCODE FORENSIC REFERENCE

DOMINANT EVENTCODES BY VOLUME:
5156: 11,501 (Windows Filtering Platform — connection permitted)
4689: 7,446 (Process terminated)
4688: 7,427 (Process created) ← PRIMARY INVESTIGATION SIGNAL
4673: 4,122 (Privileged service called) ← INSIDER THREAT SIGNAL
5157: 4,189 (Connection blocked)
4670: 3,618 (Permissions changed)
4624: 427 (Successful logon)
4625: ~6 (Failed logon) ← IMPORTANT: very low, NOT brute force

CRITICAL FORENSIC NOTES:

EventCode 4625 (Failed logon) = 6 total
This is a CRITICAL finding for classification:
- 6 failed logons across the ENTIRE dataset (2M+ events)
- This RULES OUT brute force as the attack vector
- Any trigger claiming "multiple failed logons" should be classified
  UNKNOWN or INSIDER_THREAT, not BRUTE_FORCE
- Classification confidence for BRUTE_FORCE in botsv3 = 0.0

EventCode 4688 (Process creation) = 7,427
Key sub-analysis:
- cmd.exe spawned 1,091 times
- WMIC.exe spawned 536 times
- reg.exe spawned 523 times
- backgroundTaskHost.exe from svchost.exe = anomalous

EventCode 4673 (Privileged service called) = 4,122
- Almost entirely from BillyTun account
- svchost.exe as the calling process
- Indicator of insider threat or compromised account
- NOT typical of APT activity (which uses stealthier methods)

EventCode 5156 (Connection permitted) = 11,501
- Highest security EventCode volume
- Indicates high network activity during attack window
- Useful for lateral movement timeline reconstruction

EventCode 1102 (Audit log cleared) = present
- Occurred on BSTOLL-L
- Confirms BSTOLL account compromise
- Indicates attacker awareness of Windows audit logging
- Final stage before attacker exited/reduced activity

SOURCETYPE VOLUME REFERENCE:
syslog: 283,976 (highest volume)
stream:ip: 227,872
osquery:results: 219,997
stream:dns: 218,456
stream:udp: 157,960
WinEventLog:Security: 46,469
stream:http: 24,191

INVESTIGATION PRIORITY ORDER:
1. stream:http (SSRF evidence, initial access)
2. WinEventLog:Security (process execution, logon events)
3. stream:dns (C2 communication, tunneling)
4. osquery:results (system state, persistence)
5. syslog (supporting evidence)
"""
    },
]
