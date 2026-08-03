# SOC Detection Engineering Lab

> A detection engineering project built against real, MITRE ATT&CK-mapped attack
> telemetry — 6 custom Sigma rules, confirmed true positive alerts, 3 incident
> response reports, and a SOAR containment playbook.

[![Techniques](https://img.shields.io/badge/ATT%26CK%20Techniques-6-red)](detections/)
[![Rules](https://img.shields.io/badge/Sigma%20Rules-6-blue)](detections/)
[![IR Reports](https://img.shields.io/badge/IR%20Reports-3-green)](ir-reports/)
[![Gitleaks](https://img.shields.io/badge/Secret%20Scanning-gitleaks-black)](docs/methodology.md)

---

## Detection Coverage

| Technique | ATT&CK ID | Sigma Rule | Alert Result | IR Report |
|---|---|---|---|---|
| Process Memory Access (Credential Dump) | T1003 | [rule](detections/T1003_credential_dumping/sigma_rule.yml) | ✅ 1 alert fired | [IR-001](ir-reports/IR-001-credential-dumping.md) |
| Kerberos Pre-Auth Failure (Password Spray) | T1558 | [rule](detections/T1558_kerberoasting/sigma_rule.yml) | ✅ 2 alerts fired | [IR-002](ir-reports/IR-002-kerberoasting.md) |
| Pass-the-Hash (Special Privilege Logon) | T1550 | [rule](detections/T1550_pass_the_hash/sigma_rule.yml) | ✅ 1 alert fired | — |
| Process Injection (CreateRemoteThread) | T1055 | [rule](detections/T1055_process_injection/sigma_rule.yml) | ✅ 1 alert fired | — |
| Obfuscated PowerShell (Script Block) | T1059 | [rule](detections/T1059_powershell/sigma_rule.yml) | ✅ 1 alert fired | — |
| Lateral Movement via PsExec Named Pipe | T1021 | [rule](detections/T1021_lateral_movement/sigma_rule.yml) | ✅ 1 alert fired | [IR-003](ir-reports/IR-003-lateral-movement.md) |

---

## How to Reproduce

```bash
# 1. Clone the repo
git clone https://github.com/mukundhasuresh/SOC-LAB.git
cd SOC-LAB

# 2. Install dependencies
pip install python-evtx
# Download Zircolite from https://github.com/wagga40/Zircolite/releases

# 3. Download attack telemetry datasets (git-ignored, stays local)
bash scripts/fetch_datasets.sh

# 4. Run all Sigma rules against the datasets
bash scripts/run_detections.sh
```

---

## Project Structure

```text
soc-detection-lab/
├── detections/ # 6 Sigma rules + evidence per technique
├── ir-reports/ # 3 full incident response reports
├── soar/ # Shuffle SOAR playbook for automated containment
├── datasets/ # Dataset manifest + fetch script
├── scripts/ # fetch_datasets.sh + run_detections.sh
└── docs/ # Architecture diagram + methodology
```


---

## Key Design Decisions

**No VMs, no Splunk Enterprise** — by design. This project uses real, pre-recorded
MITRE ATT&CK-mapped attack telemetry and runs detection rules with Zircolite, a
standalone Sigma engine. Any reviewer can clone this repo and reproduce every
detection in under 10 minutes on any OS. See [docs/methodology.md](docs/methodology.md).

**Sigma over vendor-specific queries** — Sigma rules are portable across Splunk,
Elastic, Microsoft Sentinel, and QRadar. Writing vendor-neutral rules is the current
SOC industry standard for detection engineering.

**Evidence is verified, not claimed** — every `test_evidence.md` contains real
Zircolite JSON output from running the rule against the actual EVTX sample.

**No personal or system data committed** — gitleaks pre-commit hook runs on every
commit. All evidence files use placeholder hostnames (WKSTN01, WKSTN02), usernames
(jdoe), and domains (corp.local). See [docs/methodology.md](docs/methodology.md).

---

## Tools & References

| Tool | Purpose | Link |
|---|---|---|
| Sigma | Detection rule format | github.com/SigmaHQ/sigma |
| Zircolite | Sigma-on-EVTX engine | github.com/wagga40/Zircolite |
| EVTX-ATTACK-SAMPLES | Attack telemetry datasets | github.com/sbousseaden/EVTX-ATTACK-SAMPLES |
| Shuffle | SOAR platform | shuffler.io |
| Gitleaks | Secret scanning | github.com/gitleaks/gitleaks |
| MITRE ATT&CK | Threat framework | attack.mitre.org |

---
