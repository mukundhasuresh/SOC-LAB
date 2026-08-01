# Methodology — Why No VMs, No Splunk Enterprise

This lab deliberately avoids spinning up Windows Server VMs or installing Splunk Enterprise.
That is an intentional engineering choice, not a limitation.

## Approach

Instead of generating attack telemetry live, this project uses real, pre-recorded,
MITRE ATT&CK-mapped attack logs from public security research datasets. The same
datasets are used by Sigma rule maintainers and SIEM vendors to validate detection logic.

Detection rules (Sigma format) are tested against these log files using **Zircolite**,
a standalone Python tool that runs Sigma rules directly against EVTX/JSON log files —
no SIEM server required.

## Why this is more portfolio-relevant

- Fully reproducible: anyone can clone this repo, run `fetch_datasets.sh`, and validate
  every detection fires correctly
- Portable: no VM snapshots, no proprietary SIEM state, no infrastructure to rebuild
- CI-friendly: the detection pipeline can run in a GitHub Actions workflow
- Mirrors real SOC work: analysts run detection logic against ingested telemetry, not
  against live environments they built themselves

## Datasets used

| Dataset | Source | Coverage |
|---|---|---|
| EVTX-ATTACK-SAMPLES | github.com/sbousseaden/EVTX-ATTACK-SAMPLES | Per-technique EVTX files |
| Security-Datasets (Mordor) | github.com/OTRF/Security-Datasets | ATT&CK-mapped JSON telemetry |

## Privacy and safety

No personal information, system hostnames, local file paths, or identifying data appears
in this repository. All placeholder values follow the convention: WKSTN01, CORP\jdoe,
10.0.0.0/24. A gitleaks pre-commit hook enforces this on every commit.
