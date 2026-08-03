## Detection Evidence — T1003 Credential Access (Process Memory Access)

**Rule:** sigma_rule.yml — Suspicious Process Memory Access via Sysmon
**Dataset:** datasets_raw/T1003_lsass_access.evtx (sbousseaden/EVTX-ATTACK-SAMPLES)
**Tool:** Zircolite + Sigma
**Result:** ✅ 1 alert fired

### Alert Output

```json
{
  "title": "Suspicious Process Memory Access via Sysmon (Credential Access Pattern)",
  "rule_level": "high",
  "tags": ["attack.credential_access", "attack.t1003"],
  "count": 1,
  "matches": [
    {
      "EventID": 10,
      "Computer": "WKSTN01",
      "UtcTime": "2020-07-24 17:20:29.871",
      "SourceImage": "C:\\Users\\analyst\\AppData\\Local\\Temp\\frida-[hash]\\frida-win32.dll",
      "TargetImage": "C:\\Program Files (x86)\\TeamViewer\\TeamViewer.exe",
      "GrantedAccess": "0x147a",
      "RuleName": "Credential Access - TeamViewer MemAccess",
      "Channel": "Microsoft-Windows-Sysmon/Operational"
    }
  ]
}
```

### Detection Logic
Sysmon Event ID 10 (ProcessAccess) fired on GrantedAccess value `0x147a` — a bitmask
consistent with credential theft tooling (PROCESS_VM_READ + PROCESS_QUERY_INFORMATION).
The Frida instrumentation framework accessed TeamViewer's process memory, a technique
used to extract credentials from running applications.

### Analyst Verdict
**TRUE POSITIVE** — Unauthorized process memory access with credential-theft access
rights. An analyst would cross-reference the SourceImage path (temp folder, random hash
in name) against known software inventory. A Frida DLL in AppData\Temp is not a
legitimate application signature. Escalate for host triage.
