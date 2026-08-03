## Detection Evidence — T1055 Defense Evasion (Process Injection)

**Rule:** sigma_rule.yml — Remote Thread Created in Remote Process
**Dataset:** datasets_raw/T1055_process_injection.evtx (sbousseaden/EVTX-ATTACK-SAMPLES)
**Tool:** Zircolite + Sigma
**Result:** ✅ 1 alert fired

### Alert Output

```json
{
  "title": "Process Injection — Remote Thread Created in Remote Process (Sysmon EID 8)",
  "rule_level": "high",
  "tags": ["attack.defense_evasion", "attack.privilege_escalation", "attack.t1055"],
  "count": 1,
  "matches": [
    {
      "EventID": 8,
      "Computer": "WKSTN02",
      "UtcTime": "2019-04-30 07:26:34.133",
      "SourceImage": "\\\\FILESVR\\Tools\\m.exe",
      "TargetImage": "C:\\Windows\\explorer.exe",
      "NewThreadId": 840,
      "StartAddress": "0x02060000",
      "Channel": "Microsoft-Windows-Sysmon/Operational"
    }
  ]
}
```

### Detection Logic
Sysmon Event ID 8 (CreateRemoteThread) fired: a binary executed from a network share
(\\FILESVR\Tools\m.exe) injected a remote thread into explorer.exe. Executing from a
UNC path and injecting into a trusted host process (explorer.exe) are both high-confidence
indicators — legitimate software does not typically load from network shares and inject
threads into shell processes.

### Analyst Verdict
**TRUE POSITIVE** — A network-share-resident executable injected code into explorer.exe.
An analyst would immediately isolate the host, identify what \\FILESVR\Tools\m.exe is,
check for persistence mechanisms written by the injected thread, and review network
connections from explorer.exe post-injection.
