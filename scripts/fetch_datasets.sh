#!/usr/bin/env bash
# fetch_datasets.sh
# Downloads MITRE ATT&CK mapped EVTX samples from public security research repos.
# Raw files are saved to datasets_raw/ which is git-ignored — never committed.

set -e

DEST="datasets_raw"
mkdir -p "$DEST"

echo "[*] Downloading T1003 — OS Credential Dumping (LSASS)"
curl -L -o "$DEST/T1003_lsass_access.evtx" \
  "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/credential_dumping_lsass_access_sysmon_10.evtx"

echo "[*] Downloading T1558 — Kerberoasting"
curl -L -o "$DEST/T1558_kerberoasting.evtx" \
  "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Credential%20Access/kerberoasting_sysmon.evtx"

echo "[*] Downloading T1550 — Pass-the-Hash"
curl -L -o "$DEST/T1550_pass_the_hash.evtx" \
  "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/pass_the_hash_detected_sysmon.evtx"

echo "[*] Downloading T1055 — Process Injection"
curl -L -o "$DEST/T1055_process_injection.evtx" \
  "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/process_injection_createremotethread_sysmon_8.evtx"

echo "[*] Downloading T1059 — Suspicious PowerShell"
curl -L -o "$DEST/T1059_powershell.evtx" \
  "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Execution/suspicious_powershell_encoded_sysmon_1.evtx"

echo "[*] Downloading T1021 — Lateral Movement (PsExec/SMB)"
curl -L -o "$DEST/T1021_lateral_movement.evtx" \
  "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/lateral_movement_psexec_sysmon.evtx"

echo ""
echo "[*] Generating SHA256 hashes..."
sha256sum "$DEST"/*.evtx > "$DEST/checksums.sha256"
cat "$DEST/checksums.sha256"

echo ""
echo "[+] All datasets downloaded to ./$DEST/"
echo "[!] These files are git-ignored and will NOT be committed."
echo "[!] Run this script again any time to re-download them."
