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

| Technique | ATT&CK ID | Dataset file | Hash |
|---|---|---|---|
| OS Credential Dumping | T1003 | datasets_raw/T1003_lsass_access.evtx | sha256:6cd4099b91daf942bdaf04a09e2266d088f807222cd3e09d344e5c92c1ee92de |
| Kerberoasting | T1558 | datasets_raw/T1558_kerberoasting.evtx | sha256:4d2132ca5668727ef1d5b8f304573251d129a53e25246d07ee4f40963f884319 |
| Pass-the-Hash | T1550 | datasets_raw/T1550_pass_the_hash.evtx | sha256:ae98a68432ba394a9091577a7cc3902549a23cdae1eecebdcce81f9a7f0a217e |
| Process Injection | T1055 | datasets_raw/T1055_process_injection.evtx | sha256:b6b3cf200bb6b232d856612c94db2eebf3c8e714250a9db1a9aab7e94b492bf3 |
| Suspicious PowerShell | T1059 | datasets_raw/T1059_powershell.evtx | sha256:b4af7076b6511ecfa064bb7ead2d7a52af565c9ea67576c8ea6811d136098d28 |
| Lateral Movement (SMB/WMI) | T1021 | datasets_raw/T1021_lateral_movement.evtx | sha256:183ce716f3373537aeb3dd46fab73e4d29427aa56dd0772f167febaa92576df9 |
