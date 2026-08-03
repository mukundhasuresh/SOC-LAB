#!/usr/bin/env bash
# fetch_datasets.sh
# Downloads real MITRE ATT&CK mapped EVTX samples.
# Files saved to datasets_raw/ which is git-ignored — never committed.

set -e
DEST="datasets_raw"
mkdir -p "$DEST"

BASE="https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master"

echo "[*] T1003 — Credential Dumping (LSASS via teamviewer-dumper, Sysmon EID 10)"
curl -L --fail -o "$DEST/T1003_lsass_access.evtx" \
  "$BASE/Credential%20Access/CA_teamviewer-dumper_sysmon_10.evtx"

echo "[*] T1558 — Kerberoasting (Security EID 4769)"
curl -L --fail -o "$DEST/T1558_kerberoasting.evtx" \
  "$BASE/Credential%20Access/kerberos_pwd_spray_4771.evtx"

echo "[*] T1550 — Pass-the-Hash (Sysmon lateral movement)"
curl -L --fail -o "$DEST/T1550_pass_the_hash.evtx" \
  "$BASE/Lateral%20Movement/LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx"

echo "[*] T1055 — Process Injection (CreateRemoteThread, Sysmon EID 8)"
curl -L --fail -o "$DEST/T1055_process_injection.evtx" \
  "$BASE/Defense%20Evasion/meterpreter_migrate_to_explorer_sysmon_8.evtx"

echo "[*] T1059 — Suspicious PowerShell (encoded command, Sysmon EID 1)"
curl -L --fail -o "$DEST/T1059_powershell.evtx" \
  "$BASE/Other/emotet/exec_emotet_ps_4104.evtx"

echo "[*] T1021 — Lateral Movement PsExec (Sysmon)"
curl -L --fail -o "$DEST/T1021_lateral_movement.evtx" \
  "$BASE/Lateral%20Movement/LM_sysmon_psexec_smb_meterpreter.evtx"

echo ""
echo "[*] Generating SHA256 hashes..."
sha256sum "$DEST"/*.evtx > "$DEST/checksums.sha256"
cat "$DEST/checksums.sha256"

echo ""
echo "[+] Done. Files in ./$DEST/ (git-ignored, not committed)"
