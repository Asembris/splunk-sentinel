# Splunk Sentinel App

Splunk app package for the Splunk Sentinel autonomous
SOC investigation platform.

## One-Click Installation

### Option A - Install via .spl file (recommended)

1. Download sentinel.spl from the repo root
2. Open Splunk UI at http://localhost:8000
3. Apps -> Manage Apps -> Install app from file
4. Upload sentinel.spl
5. Check "Upgrade app" if prompted
6. Click Upload
7. Restart Splunk when prompted
8. Navigate to Apps -> Splunk Sentinel to confirm

### Option B - Manual copy

1. Copy splunk_sentinel_app/ to:
   Windows: C:\Program Files\Splunk\etc\apps\
   Linux:   /opt/splunk/etc/apps/
2. Restart Splunk:
   Windows: net stop SplunkForwarder && net start SplunkForwarder
            OR restart via Services
   Linux:   /opt/splunk/bin/splunk restart
3. Open http://localhost:8000
4. Navigate to Apps -> Splunk Sentinel

## What Gets Installed

### Indexes
- sentinel_findings - stores completed investigation
  findings as Splunk notable events
- sentinel_actions - audit trail for every containment
  action executed by Sentinel

### Dashboard
- 4-panel native Splunk dashboard showing:
  - Recent Investigations (from sentinel_findings)
  - Attack Classification Breakdown (pie chart)
  - Containment Actions Audit (from sentinel_actions)
  - Investigations Over Time (bar chart)

### Saved Searches
- Sentinel - AWS Metadata Access Detected
  Detects SSRF attacks targeting AWS metadata service
  Configure alert action to POST to:
  http://localhost:8001/api/webhook/splunk
  for autonomous investigation triggering

### MLTK Permissions
- authorize.conf grants role_admin the 3 capabilities
  required for the MLTK ai SPL command:
  - apply_ai_commander_command
  - list_ai_commander_config
  - edit_ai_commander_config

## Prerequisites

- Splunk Enterprise 9.x or 10.x
- MLTK 5.7.4 (Splunk AI Toolkit) installed
- Python for Scientific Computing 4.3.2 (Windows) installed
- Splunk Sentinel backend running on port 8001

## Verify Installation

Run these in Splunk Search to confirm indexes exist:

```spl
| rest /services/data/indexes
| where title="sentinel_findings" OR title="sentinel_actions"
| table title, totalEventCount, currentDBSizeMB
```

Expected: 2 rows returned.

Verify MLTK permissions:
```spl
| makeresults count=1
| eval test="MLTK permissions verified"
| ai connection="openai_sentinel"
    prompt="Say: MLTK working. {test}"
```

Expected: ai_result_1 field appears.
