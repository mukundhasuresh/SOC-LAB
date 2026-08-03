# SOAR Playbook — Automated Containment on Pass-the-Hash Detection

## Overview
This playbook triggers automatically when the T1550 Pass-the-Hash Sigma rule fires.
It performs enrichment, notification, and simulated containment without waiting for
manual analyst intervention — reducing dwell time from detection to response.

## Trigger Condition
- **Alert:** Pass-the-Hash — Special Privileges Assigned to New Logon
- **Rule:** detections/T1550_pass_the_hash/sigma_rule.yml
- **Severity threshold:** High
- **SIEM:** Wazuh / any SIEM ingesting Sysmon + Security event logs

## Automated Workflow Steps

| Step | Action | Tool | Output |
|---|---|---|---|
| 1 | Alert received from SIEM | Shuffle trigger | Incident created |
| 2 | Enrich source IP | VirusTotal (free API) | Reputation score, known malicious? |
| 3 | Enrich username | Active Directory lookup | Account details, group memberships |
| 4 | Notify SOC channel | Webhook → Slack/Teams | Alert summary with enrichment |
| 5 | Simulate account disable | Mock HTTP endpoint | Account disable request logged |
| 6 | Create ticket | Shuffle HTTP action | IR ticket auto-created |
| 7 | Log action taken | Shuffle output | Full audit trail |

## Why This Matters
Manual triage of a Pass-the-Hash alert takes 5–15 minutes minimum. An attacker
with a valid hash can move laterally to multiple hosts in that window. Automating
steps 1–4 cuts analyst workload to a single confirmation click, and auto-disabling
the account (step 5) stops credential reuse immediately — before lateral movement
completes.

## Playbook File
See `shuffle-playbook-disable-account.json` for the exportable Shuffle workflow.
Import into Shuffle (cloud free tier at shuffler.io) to deploy.

## Security Note
The JSON playbook uses placeholder values for all endpoints and API keys.
Replace the following before deploying in a real environment:
- `YOUR_VIRUSTOTAL_API_KEY` → real VT API key (store in Shuffle secrets, never hardcode)
- `YOUR_WEBHOOK_URL` → real Slack/Teams incoming webhook URL
- `YOUR_MOCK_AD_ENDPOINT` → real AD/identity provider API endpoint

---
