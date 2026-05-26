# Splunk Sentinel App

## Installation

Option A - Copy to Splunk apps directory:
1. Copy `splunk_sentinel_app/` to `C:\Program Files\Splunk\etc\apps\` (Windows) or `/opt/splunk/etc/apps/` (Linux)
2. Restart Splunk:
   - Windows: Restart the Splunk service
   - Linux: `/opt/splunk/bin/splunk restart`
3. Open `http://localhost:8000`
4. Navigate to Apps -> Splunk Sentinel
5. The dashboard loads automatically

Option B - Install via `.spl` file
(when `sentinel.spl` is available at repo root):
1. Open the Splunk UI
2. Apps -> Manage Apps -> Install app from file
3. Upload `sentinel.spl`
4. Restart Splunk when prompted

## Prerequisites

- Splunk Enterprise 9.x or 10.x
- `sentinel_findings` index must exist
- `sentinel_actions` index must exist
- At least one completed investigation run via the Splunk Sentinel backend

## What the Dashboard Shows

- Recent Investigations: latest 10 investigations with classification, severity, and kill chain
- Attack Classification Breakdown: pie chart of APT vs Ransomware vs Insider Threat distribution
- Containment Actions Audit: latest 20 containment actions with verification verdicts
- Investigations Over Time: daily investigation count by classification

## Indexes Required

- `sentinel_findings`: created automatically by the Splunk Sentinel backend on startup
- `sentinel_actions`: created automatically by the Splunk Sentinel backend on startup
