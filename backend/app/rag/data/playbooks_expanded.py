EXPANDED_PLAYBOOKS = [
    {
        "id": "playbook-apt-cloud-credential-theft",
        "title": "APT: Cloud Credential Theft via SSRF",
        "attack_type": "APT",
        "trigger": "AWS metadata service access from internal host via SSRF",
        "mitre_techniques": ["T1552.005", "T1190", "T1528"],
        "content": """
INCIDENT RESPONSE PLAYBOOK: APT Cloud Credential Theft

SEVERITY: CRITICAL
TRIGGER: HTTP requests to 169.254.169.254 from internal hosts

PHASE 1 — IMMEDIATE CONTAINMENT (0-30 minutes)
1. Identify the source IP making requests to 169.254.169.254
2. Search stream:http: sourcetype=stream:http dest_ip=169.254.169.254
3. Isolate the compromised host in a quarantine VLAN immediately
4. Revoke ALL IAM credentials associated with the compromised EC2 role
5. Rotate the EC2 instance role — create new role, detach old
6. Check CloudTrail for any API calls made with stolen credentials

PHASE 2 — INVESTIGATION (30-120 minutes)
1. Determine exact URI paths accessed on metadata service
   Focus on: /latest/meta-data/iam/security-credentials/
2. Identify which IAM role credentials were exposed
3. Search CloudTrail for all API calls from stolen access key
   Time window: from first SSRF to role rotation
4. Check for new IAM users, access keys, or role modifications
5. Identify the vulnerable web application that allowed SSRF
   Review stream:http for requests to the compromised host

PHASE 3 — ERADICATION
1. Patch the vulnerable web application causing SSRF
2. Implement IMDSv2 (Instance Metadata Service v2) on all EC2 instances
   IMDSv2 requires a session token — prevents SSRF exploitation
3. Add WAF rules blocking requests with 169.254.169.254 in path
4. Review all EC2 instance roles — apply least privilege
5. Enable AWS GuardDuty if not already active

PHASE 4 — RECOVERY
1. Rebuild compromised EC2 instance from known-good AMI
2. Implement network segmentation preventing SSRF to metadata
3. Add CloudTrail alerting for credential use from unexpected IPs
4. Schedule IMDSv2 migration for all EC2 fleet

INDICATORS OF COMPROMISE
- HTTP requests to 169.254.169.254 from internal RFC1918 addresses
- URI path: /latest/meta-data/iam/security-credentials/
- HTTP 200 responses to metadata service (credential retrieval confirmed)
- Subsequent AWS API calls from unexpected IP geolocation
- EventCode 4688: unusual process spawning after web server activity
"""
    },
    {
        "id": "playbook-apt-initial-access-web",
        "title": "APT: Initial Access via Public-Facing Web Application",
        "attack_type": "APT",
        "trigger": "Exploit of public-facing web application detected",
        "mitre_techniques": ["T1190", "T1059.003", "T1505.003"],
        "content": """
INCIDENT RESPONSE PLAYBOOK: APT Web Application Initial Access

SEVERITY: HIGH
TRIGGER: Anomalous HTTP requests indicating web application exploitation

PHASE 1 — DETECTION VALIDATION (0-15 minutes)
1. Confirm exploit attempt via web server logs and stream:http
2. Identify the exploited endpoint and vulnerability class
   Common patterns: SQL injection, file upload, SSTI, OGNL injection
3. Determine if exploitation was successful
   Look for: unusual process spawning (EventCode 4688) from web server
   Look for: web shell creation (new .php/.aspx files in web root)
   Look for: outbound connections from web server process

PHASE 2 — CONTAINMENT (15-60 minutes)
1. Block the attacker's source IP at the perimeter firewall
2. If web shell confirmed: take web server offline immediately
3. Preserve logs before any remediation: web server, OS, network
4. Snapshot the compromised system for forensic analysis
5. Block outbound connections from web server to unknown IPs

PHASE 3 — INVESTIGATION
1. Identify all files created or modified since exploitation
2. Check process tree: what processes did the web server spawn?
   SPL: index=botsv3 sourcetype=WinEventLog:Security EventCode=4688
        | where Creator_Process_Name like "%w3wp%"
        OR Creator_Process_Name like "%httpd%"
3. Review all authentication events post-exploitation
4. Check for lateral movement: EventCode 4648, 4624 Type 3
5. Identify data accessed or exfiltrated

PHASE 4 — ERADICATION
1. Remove web shell and any dropped tools
2. Patch the exploited vulnerability
3. Conduct full malware scan on web server
4. Review all web application dependencies for additional CVEs

INDICATORS OF COMPROMISE
- Unusual HTTP status codes (200 on normally restricted endpoints)
- Command injection characters in HTTP parameters (;, |, &&)
- Web server process spawning cmd.exe or powershell.exe
- New files in web root with script extensions
- Outbound connections from web server on unusual ports
"""
    },
    {
        "id": "playbook-apt-c2-beaconing",
        "title": "APT: Command and Control Beaconing Detection",
        "attack_type": "APT",
        "trigger": "Periodic outbound connections suggesting C2 communication",
        "mitre_techniques": ["T1071.001", "T1071.004", "T1573"],
        "content": """
INCIDENT RESPONSE PLAYBOOK: APT C2 Beaconing

SEVERITY: HIGH
TRIGGER: Regular interval outbound connections to external infrastructure

PHASE 1 — DETECTION (0-30 minutes)
1. Identify beaconing pattern via DNS or HTTP logs
   DNS: stream:dns showing repeated queries to same domain
   HTTP: stream:http showing periodic requests to same dest_ip
2. Calculate beacon interval (common: 60s, 300s, 3600s)
3. Identify the process making outbound connections
   EventCode 5156 (Windows Filtering Platform) + 4688 correlation
4. Determine if traffic is encrypted (HTTPS/DNS-over-HTTPS)

PHASE 2 — CONTAINMENT (30-60 minutes)
1. Block the C2 destination at perimeter firewall and DNS
2. Isolate the beaconing host in quarantine VLAN
3. Do NOT kill the malicious process yet — preserve for forensics
4. Enable enhanced packet capture on the isolated host
5. Notify threat intelligence team — share IOCs for industry sharing

PHASE 3 — INVESTIGATION
1. Identify all processes spawned by the C2 implant
2. Check for persistence mechanisms:
   EventCode 4698 (scheduled task created)
   Registry run keys via EventCode 4657
   Service installation via EventCode 7045
3. Determine initial access vector — how did implant arrive?
4. Check for lateral movement from beaconing host
5. Identify any data staged for exfiltration

PHASE 4 — ERADICATION
1. Collect memory dump before terminating implant
2. Remove all persistence mechanisms
3. Block C2 infrastructure at all perimeter controls
4. Rebuild host from known-good image
5. Implement network segmentation preventing direct outbound

INDICATORS OF COMPROMISE
- Regular interval HTTP requests (jitter < 10%) to external IP
- DNS queries with high-entropy domain names (DGA)
- Small consistent payload sizes (< 1KB per beacon)
- Non-standard User-Agent strings
- HTTPS to non-standard ports (not 443)
- Long-lived TCP connections with low data transfer
"""
    },
    {
        "id": "playbook-ransomware-pre-encryption",
        "title": "Ransomware: Pre-Encryption Staging Detection",
        "attack_type": "RANSOMWARE",
        "trigger": "Shadow copy deletion, lateral movement, or ransomware staging indicators",
        "mitre_techniques": ["T1490", "T1021.002", "T1486", "T1059.003"],
        "content": """
INCIDENT RESPONSE PLAYBOOK: Ransomware Pre-Encryption Staging

SEVERITY: CRITICAL — TIME SENSITIVE
TRIGGER: Indicators of ransomware staging before encryption begins

CRITICAL: If you detect these indicators, you have minutes to hours
before encryption begins. Every action must be taken immediately.

PHASE 1 — EMERGENCY CONTAINMENT (0-15 minutes)
1. Identify affected hosts via lateral movement indicators
2. IMMEDIATELY disconnect all affected hosts from network
   Do not shut down — disconnection preserves encryption keys in memory
3. Suspend all backup jobs — ransomware targets backup servers
4. Alert all IT staff — declare P1 incident

STAGE INDICATORS TO CHECK IMMEDIATELY:
- vssadmin delete shadows /all /quiet (EventCode 4688)
- wmic shadowcopy delete (EventCode 4688)
- bcdedit /set {default} recoveryenabled no (EventCode 4688)
- net use \\ commands indicating lateral movement
- PsExec, Cobalt Strike, or similar tool execution

PHASE 2 — INVESTIGATION (15-45 minutes)
1. Determine patient zero — which host was compromised first?
2. Map all hosts with lateral movement from patient zero
3. Identify the ransomware variant from process names and IOCs
4. Determine dwell time — when did attacker first enter network?
5. Check for data exfiltration before encryption (double extortion)

PHASE 3 — CONTAINMENT EXPANSION
1. Isolate all identified hosts in quarantine VLAN
2. Change all service account passwords immediately
3. Disable all compromised user accounts
4. Reset krbtgt password twice (prevents Golden Ticket attacks)
5. Block all lateral movement paths identified in investigation

INDICATORS OF COMPROMISE
- vssadmin, wbadmin, or bcdedit with destructive parameters
- Mass EventCode 4688 for net.exe, cmd.exe across multiple hosts
- SMB traffic (EventCode 5156) from unexpected sources
- New service installations (EventCode 7045) across hosts
- Large volume of file renames in short time window
"""
    },
    {
        "id": "playbook-ransomware-active-encryption",
        "title": "Ransomware: Active Encryption Response",
        "attack_type": "RANSOMWARE",
        "trigger": "Active file encryption detected across endpoints",
        "mitre_techniques": ["T1486", "T1490", "T1489"],
        "content": """
INCIDENT RESPONSE PLAYBOOK: Ransomware Active Encryption

SEVERITY: CRITICAL — ENCRYPTION IN PROGRESS
TRIGGER: Files being renamed with ransomware extension, ransom note dropped

IMMEDIATE ACTIONS (execute in parallel, first 5 minutes):
1. Network isolation: block all inter-VLAN routing
2. Alert leadership: this is a business continuity event
3. Contact cyber insurance provider immediately
4. Do NOT pay ransom without legal/insurance consultation
5. Preserve all logs before any remediation attempts

PHASE 1 — STOP THE SPREAD (0-10 minutes)
1. Identify encryption source via file server logs
2. Disable all user accounts except break-glass accounts
3. Shut down non-critical systems to prevent encryption
4. Identify and isolate file shares being encrypted
5. Block SMB (445) at all internal firewall boundaries

PHASE 2 — ASSESS DAMAGE (10-60 minutes)
1. Determine which systems are fully encrypted vs partially
2. Identify what data was encrypted — prioritize recovery
3. Check if backups are intact and offline/immutable
4. Determine if data was exfiltrated (double extortion)
5. Collect ransomware sample for variant identification

PHASE 3 — RECOVERY PREPARATION
1. Identify clean systems that can be used for recovery
2. Validate backup integrity before restoration attempt
3. Engage ransomware specialist if needed
4. Prepare clean environment for restoration
5. Document all affected systems and data for insurance claim

INDICATORS OF ACTIVE ENCRYPTION
- Mass file rename events (thousands per minute)
- New file extension appearing (*.locked, *.encrypted, *.WNCRY)
- Ransom note files (README.txt, DECRYPT_INSTRUCTIONS.html)
- High disk I/O on file servers
- EventCode 4663 (object access) at extreme volume
"""
    },
    {
        "id": "playbook-insider-data-exfiltration",
        "title": "Insider Threat: Data Exfiltration Detection",
        "attack_type": "INSIDER_THREAT",
        "trigger": "Bulk file access or unusual data transfer by internal account",
        "mitre_techniques": ["T1005", "T1052", "T1048", "T1567"],
        "content": """
INCIDENT RESPONSE PLAYBOOK: Insider Threat Data Exfiltration

SEVERITY: HIGH
TIMEFRAME: Covert investigation — do not alert the subject

CRITICAL: Notify HR and Legal BEFORE taking any action.
Preserve evidence for potential legal proceedings.

PHASE 1 — COVERT EVIDENCE PRESERVATION (0-24 hours)
1. Do NOT confront the subject or alert them
2. Enable enhanced auditing on subject's account immediately
3. Preserve all existing logs before rotation occurs
4. Enable DLP monitoring on subject's email and endpoints
5. Document all findings in a legal-hold evidence folder

EXFILTRATION INDICATORS TO INVESTIGATE:
- Bulk file access: EventCode 4663 > normal baseline by 10x
- USB device connection: EventCode 6416 (device attached)
- Large email attachments sent to personal email
- Cloud storage uploads (OneDrive, Dropbox, Google Drive)
- Printing sensitive documents: EventCode 4663 on print spool
- Access to files outside normal job function

PHASE 2 — INVESTIGATION (24-72 hours)
1. Review EventCode 4663 for sensitive file access patterns
2. Check email logs for large outbound attachments
3. Review web proxy logs for cloud storage uploads
4. Check USB device events on subject's workstation
5. Cross-reference with physical access logs and VPN records
6. Review EventCode 4670 for permission changes on sensitive data

PHASE 3 — CONTAINMENT (after legal review)
1. Coordinate account suspension timing with HR/Legal
2. Preserve all evidence before any account action
3. Revoke VPN, remote access, and cloud credentials simultaneously
4. Change passwords for all shared accounts subject had access to
5. Review and revoke all API keys associated with the subject

INDICATORS OF COMPROMISE
- EventCode 4663 bulk file access outside business hours
- EventCode 6416 USB device connection on sensitive workstation
- Large outbound email (> 10MB) to personal domains
- Cloud sync application activity on corporate device
- Access to files in departments outside subject's role
"""
    },
    {
        "id": "playbook-insider-privilege-abuse",
        "title": "Insider Threat: Privileged Service Abuse",
        "attack_type": "INSIDER_THREAT",
        "trigger": "EventCode 4673 privileged service calls outside business hours",
        "mitre_techniques": ["T1078", "T1098", "T1548"],
        "content": """
INCIDENT RESPONSE PLAYBOOK: Insider Privilege Abuse

SEVERITY: HIGH
TRIGGER: Privileged service calls (EventCode 4673) from internal account
outside normal business hours with no operational justification

PHASE 1 — DETECTION VALIDATION (0-2 hours)
1. Confirm EventCode 4673 pattern is anomalous
   Compare to historical baseline for the account
   Check if the activity matches any scheduled maintenance
2. Identify which privileged services were called
   SeBackupPrivilege, SeDebugPrivilege, SeTcbPrivilege are critical
3. Identify the process making privileged calls (Process_Name field)
4. Check if the account has legitimate need for these privileges

PHASE 2 — COVERT INVESTIGATION (2-24 hours)
1. Notify HR and Legal before taking any action
2. Enable enhanced auditing — do not alert the subject
3. Review EventCode 4672 (special privileges assigned at logon)
4. Review EventCode 4688 — what processes did subject execute?
5. Check EventCode 4663 — what files did subject access?
6. Review EventCode 4670 — did subject change any permissions?

PHASE 3 — SCOPE ASSESSMENT
1. Determine what data or systems were accessed
2. Identify if any credentials were harvested
3. Check for any changes to other accounts (EventCode 4720, 4732)
4. Review system configuration changes
5. Determine business impact of unauthorized access

PHASE 4 — CONTAINMENT (after legal authorization)
1. Coordinate with HR on timing of account suspension
2. Revoke all privileged access simultaneously
3. Reset passwords for any shared privileged accounts
4. Review all PAM (Privileged Access Management) policies
5. Implement just-in-time (JIT) privilege access going forward

INDICATORS OF COMPROMISE
- EventCode 4673: privileged service calls outside business hours
- EventCode 4672 with SeBackupPrivilege or SeDebugPrivilege
- Process_Name inconsistent with account's job function
- EventCode 4688: administrative tools (regedit, cmd) run by non-admin
- Multiple EventCode 4673 from single account in short window
"""
    },
    {
        "id": "playbook-defense-evasion-log-clearing",
        "title": "Defense Evasion: Security Log Clearing Detection",
        "attack_type": "APT",
        "trigger": "EventCode 1102 security audit log cleared",
        "mitre_techniques": ["T1070.001", "T1562.002"],
        "content": """
INCIDENT RESPONSE PLAYBOOK: Security Log Clearing

SEVERITY: CRITICAL
TRIGGER: EventCode 1102 (Security audit log cleared) detected

CRITICAL NOTE: Log clearing is almost always malicious. Legitimate
administrators clear logs through Group Policy, not manually.
Treat every EventCode 1102 as a confirmed incident until proven otherwise.

PHASE 1 — IMMEDIATE RESPONSE (0-15 minutes)
1. Identify EXACTLY when the log was cleared (EventCode 1102 timestamp)
2. Identify WHO cleared the log (Subject Account Name field)
3. The clearing event itself is preserved — it cannot be deleted
4. Forward all remaining logs to SIEM immediately before any further clearing
5. Enable remote log forwarding if not already active

INVESTIGATION APPROACH:
Since the security log was cleared, use alternative evidence sources:
- System event log: EventCode 7045 (service installation)
- Application event log: application errors, crashes
- PowerShell operational log: script execution
- WMI activity log: WMI process execution
- Sysmon logs if deployed
- Network logs: stream:http, stream:dns for activity timeline

PHASE 2 — TIMELINE RECONSTRUCTION
1. Establish what happened BEFORE the clearing using:
   - Firewall logs (EventCode 5156, 5157)
   - Process creation (EventCode 4688) from System log
   - Network connection logs
   - File system timestamps
2. Identify the attack stage when log was cleared
   Log clearing typically occurs during Defense Evasion stage
3. Determine what evidence the attacker was trying to destroy

PHASE 3 — CONTAINMENT
1. Isolate the host where log clearing occurred
2. Disable the account that performed the clearing
3. Conduct memory forensics before shutdown
4. Check all other hosts for similar EventCode 1102
5. Review if attacker has access to other systems

INDICATORS OF COMPROMISE
- EventCode 1102: Security audit log cleared (the trigger itself)
- EventCode 104: System log cleared
- Absence of expected EventCodes in a time window (gap in logs)
- Account clearing logs is not in IT admin group
- Log clearing followed immediately by lateral movement
"""
    },
    {
        "id": "playbook-brute-force-password-spray",
        "title": "Brute Force: Password Spray Attack Response",
        "attack_type": "INSIDER_THREAT",
        "trigger": "Multiple failed logons across many accounts from single source",
        "mitre_techniques": ["T1110.003", "T1078", "T1133"],
        "content": """
INCIDENT RESPONSE PLAYBOOK: Password Spray Attack

SEVERITY: HIGH
TRIGGER: Low-volume failed logons (EventCode 4625) spread across
many user accounts from single or few source IPs

NOTE: Password spray differs from brute force.
Brute force: many attempts against one account
Password spray: one or few attempts against many accounts
The goal is to avoid account lockout while testing credentials.

DETECTION SPL:
index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4625
| stats count dc(Account_Name) as unique_accounts by src_ip
| where unique_accounts > 10 AND count > 20
| sort -unique_accounts

PHASE 1 — VALIDATE AND SCOPE (0-30 minutes)
1. Confirm spray pattern: many accounts, few attempts per account
2. Identify source IP(s) — internal or external?
3. Determine time window of spray activity
4. Check if any accounts had successful logon after failed attempts
   EventCode 4624 following EventCode 4625 for same account
5. Identify targeted accounts — are they privileged?

PHASE 2 — CONTAINMENT (30-60 minutes)
1. Block source IP at perimeter if external
2. If successful logon found: treat as compromised credential immediately
3. Reset passwords for all successfully sprayed accounts
4. Enable MFA for all accounts targeted in the spray
5. Alert all targeted users to watch for suspicious activity

PHASE 3 — INVESTIGATION
1. Determine if any credentials were successfully harvested
2. Check for lateral movement from any compromised accounts
3. Review VPN and remote access logs for compromised account usage
4. Determine attack origin — phishing lead? Credential dump?
5. Search for the same accounts on breach databases (HaveIBeenPwned)

INDICATORS OF COMPROMISE
- EventCode 4625 spread across > 10 unique accounts from single IP
- Logon failures outside business hours
- Logon Type 3 (network) or Type 10 (remote interactive)
- Common passwords attempted: Season+Year, Company+Year patterns
- Source IP from anonymizing infrastructure (VPN, Tor exit node)
"""
    },
    {
        "id": "playbook-lateral-movement-wmi",
        "title": "Lateral Movement: WMI and Remote Execution Detection",
        "attack_type": "APT",
        "trigger": "WMIC remote execution or WMI lateral movement indicators",
        "mitre_techniques": ["T1047", "T1021.006", "T1059.003"],
        "content": """
INCIDENT RESPONSE PLAYBOOK: WMI Lateral Movement

SEVERITY: HIGH
TRIGGER: WMIC.exe remote process execution or WMI subscription creation

PHASE 1 — DETECTION (0-30 minutes)
1. Identify WMI lateral movement via EventCode 4688:
   New_Process_Name like "%WMIC%"
   CommandLine containing "/node:" (remote execution)
2. Identify WMI subscription persistence via:
   EventCode 5861 (WMI activity - subscription created)
3. Identify remote process creation target hosts
4. Correlate with network connections (EventCode 5156) to target hosts

WMIC LATERAL MOVEMENT SPL:
index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4688
| where match(New_Process_Name, "(?i)wmic")
| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table time, ComputerName, Account_Name, New_Process_Name,
         Creator_Process_Name
| sort time

PHASE 2 — SCOPE ASSESSMENT
1. Identify all target hosts of WMI remote execution
2. Determine what commands were executed remotely
3. Check if persistent WMI subscriptions were created
4. Identify any files dropped on target hosts
5. Determine if this is part of a larger lateral movement campaign

PHASE 3 — CONTAINMENT
1. Block WMI traffic (TCP 135 + dynamic ports) between segments
2. Isolate source host of WMI lateral movement
3. Remove malicious WMI subscriptions from target hosts
4. Disable WMI service on non-essential hosts
5. Reset credentials of account used for WMI execution

PHASE 4 — ERADICATION
1. Audit all WMI subscriptions across the environment
2. Implement WMI logging and alerting via Sysmon
3. Restrict WMI access via Windows Firewall GPO
4. Enable AMSI for WMI script execution

INDICATORS OF COMPROMISE
- WMIC.exe with /node: parameter (remote execution)
- WMI process creation from non-admin accounts
- EventCode 5861: WMI subscription created
- WmiprvSE.exe spawning cmd.exe or powershell.exe
- Lateral movement pattern: same commands on multiple hosts
"""
    },
]
