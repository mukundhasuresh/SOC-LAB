# SOC Detection Engineering Lab

> A detection engineering project built against real, MITRE ATT&CK-mapped attack
> telemetry — 6 techniques, 6 custom Sigma rules, validated alerts, full incident
> response documentation, and a SOAR containment playbook.

## Detection Coverage

| Technique | ATT&CK ID | Sigma Rule | IR Report | Status |
|---|---|---|---|---|
| OS Credential Dumping | T1003 | detections/T1003_credential_dumping/sigma_rule.yml | ir-reports/IR-001 | 🔄 In Progress |
| Kerberoasting | T1558 | detections/T1558_kerberoasting/sigma_rule.yml | ir-reports/IR-002 | 🔄 In Progress |
| Pass-the-Hash | T1550 | detections/T1550_pass_the_hash/sigma_rule.yml | — | 🔄 In Progress |
| Process Injection | T1055 | detections/T1055_process_injection/sigma_rule.yml | — | 🔄 In Progress |
| Suspicious PowerShell | T1059 | detections/T1059_powershell/sigma_rule.yml | — | 🔄 In Progress |
| Lateral Movement | T1021 | detections/T1021_lateral_movement/sigma_rule.yml | ir-reports/IR-003 | 🔄 In Progress |

## How This Works

Public EVTX datasets → Zircolite + Sigma rules → Alert evidence → IR reports → SOAR playbook


1. Run `scripts/fetch_datasets.sh` to download MITRE-mapped attack telemetry locally
2. Run `scripts/run_detections.sh` to execute all Sigma rules against the datasets
3. Review fired alerts in each `detections/<technique>/test_evidence.md`

## Why No VMs / No Splunk Enterprise

This is a deliberate choice for reproducibility and portability.
See [docs/methodology.md](docs/methodology.md) for the full explanation.

## Tools Used

| Tool | Purpose |
|---|---|
| Sigma | Detection rule format (write once, run on any SIEM) |
| Zircolite | Run Sigma rules against EVTX files, no SIEM needed |
| EVTX-ATTACK-SAMPLES | Real recorded attack telemetry per ATT&CK technique |
| Wazuh (Docker, optional) | SIEM dashboard for visual evidence |
| Shuffle | SOAR playbook for automated containment |

## Repository Safety

No personal or system-identifying information is present in this repository.
A gitleaks pre-commit hook scans every commit before it lands.
