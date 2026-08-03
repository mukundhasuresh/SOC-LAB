## Detection Evidence — T1021 Lateral Movement (PsExec Named Pipe)

**Rule:** sigma_rule.yml — PsExec Named Pipe Creation
**Dataset:** datasets_raw/T1021_lateral_movement.evtx (sbousseaden/EVTX-ATTACK-SAMPLES)
**Tool:** Zircolite + Sigma
**Result:** ✅ 1 alert fired

### Alert Output

```json
{
  "title": "Lateral Movement — PsExec Named Pipe Creation (Sysmon EID 18)",
  "rule_level": "high",
  "tags": ["attack.lateral_movement", "attack.t1021", "attack.t1021.002"],
  "count": 1,
  "matches": [
    {
      "EventID": 18,
      "Computer": "WKSTN02",
      "UtcTime": "2019-04-30 20:26:51.793",
      "PipeName": "\\ntsvcs",
      "Image": "System",
      "Channel": "Microsoft-Windows-Sysmon/Operational"
    }
  ]
}
```

### Detection Logic
Sysmon Event ID 18 (PipeEvent — Pipe Connected) detected the named pipe `\ntsvcs` —
the pipe PsExec uses for communication between the attacker machine and the remote
service it installs on the target. The pipe being created by the System process confirms
this is the target-side service receiving the connection, not a client.

### Analyst Verdict
**TRUE POSITIVE** — PsExec activity confirmed on WKSTN02. An analyst would identify
the source host that connected to this pipe (correlate with EID 3 network connection
events in the same timeframe), determine what command PsExec executed, check for
PSEXESVC.exe artifacts on disk, and review what the attacker ran remotely.
