# Datasets

Raw dataset files are NOT stored in this repo (they are git-ignored).
Run `scripts/fetch_datasets.sh` to download them locally.

## Sources

### EVTX-ATTACK-SAMPLES
- Repo: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- License: See repo
- Coverage: Individual EVTX files per MITRE ATT&CK technique

### Security-Datasets (Mordor Project)
- Repo: https://github.com/OTRF/Security-Datasets
- License: MIT
- Coverage: Full attack scenario telemetry with ATT&CK metadata

## Techniques covered

| Technique | ATT&CK ID | Dataset file (after fetch) |
|---|---|---|
| OS Credential Dumping | T1003 | datasets_raw/T1003_* |
| Kerberoasting | T1558 | datasets_raw/T1558_* |
| Pass-the-Hash | T1550 | datasets_raw/T1550_* |
| Process Injection | T1055 | datasets_raw/T1055_* |
| Suspicious PowerShell | T1059 | datasets_raw/T1059_* |
| Lateral Movement (SMB/WMI) | T1021 | datasets_raw/T1021_* |
