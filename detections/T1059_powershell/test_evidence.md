## Detection Evidence — T1059 Execution (Malicious PowerShell)

**Rule:** sigma_rule.yml — Malicious PowerShell Script Block (Obfuscated)
**Dataset:** datasets_raw/T1059_powershell.evtx (sbousseaden/EVTX-ATTACK-SAMPLES)
**Tool:** Zircolite + Sigma
**Result:** ✅ 1 alert fired

### Alert Output

```json
{
  "title": "Malicious PowerShell Script Block — Obfuscated Code Execution (EID 4104)",
  "rule_level": "high",
  "tags": ["attack.execution", "attack.t1059", "attack.t1059.001"],
  "count": 1,
  "matches": [
    {
      "EventID": 4104,
      "Computer": "WKSTN03",
      "SystemTime": "2020-08-26T05:09:28.845521Z",
      "ScriptBlockText": "$Va5w3n8=(('Q'+'2h')+('w9p'+'1'));&('ne'+'w-'+'item') $eNV:teMP [truncated for brevity]",
      "ScriptBlockId": "fdd51159-9602-40cb-839d-c31039ebbc3a",
      "Channel": "Microsoft-Windows-PowerShell/Operational"
    }
  ]
}
```

### Detection Logic
PowerShell Script Block Logging (EID 4104) captured an obfuscated payload before
execution. Key indicators: string concatenation (`'ne'+'w-'+'item'`) to evade keyword
detection, mixed-case environment variable (`$eNV:teMP`), and `[Net.ServicePointManager]`
usage to configure TLS for a download cradle. EID 4104 logs the script *after*
deobfuscation by the PowerShell engine — making it reliable even against heavily
obfuscated payloads.

### Analyst Verdict
**TRUE POSITIVE** — Obfuscated PowerShell download cradle. The full ScriptBlockText
(available in the raw EVTX) contains multiple URLs for payload download, file size
validation, and execution. An analyst would extract and block all URLs, review what
was downloaded to %TEMP%\Word\2019\, and check for persistence.
