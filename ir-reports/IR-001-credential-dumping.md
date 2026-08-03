# IR-001 — Credential Access via Process Memory Inspection
**Severity:** High
**Status:** Closed (Simulated)
**ATT&CK Technique:** T1003 — OS Credential Dumping
**Detection Source:** Sigma rule — Suspicious Process Memory Access (Sysmon EID 10)
**Date:** 2020-07-24

---

## Summary
A process instrumentation tool (Frida framework) accessed the memory of a running
application with GrantedAccess rights consistent with credential theft tooling
(0x147a). Sysmon captured the ProcessAccess event via Event ID 10. The source binary
resided in a temporary directory with a randomised hash-based path — not a signature
of legitimate software.

---

## Detection Timeline

| Time (UTC) | Event |
|---|---|
| 2020-07-24 17:20:29 | Sysmon EID 10 fires — process memory access detected |
| 2020-07-24 17:20:29 | GrantedAccess 0x147a matched Sigma rule threshold |
| 2020-07-24 17:20:30 | Alert generated — SOC analyst assigned |
| T+5 min | Host isolated pending investigation |
| T+15 min | Source binary identified as Frida instrumentation DLL |
| T+30 min | Credential reset initiated for accounts accessible on host |

---

## Indicators of Compromise

| Type | Value | Significance |
|---|---|---|
| EventID | 10 (Sysmon ProcessAccess) | Core detection signal |
| GrantedAccess | 0x147a | Credential-theft access mask |
| SourceImage path pattern | AppData\Local\Temp\[random-hash]\ | Suspicious staging path |
| Tool identified | Frida instrumentation framework | Legitimate tool, malicious use |
| RuleName (Sysmon) | Credential Access - TeamViewer MemAccess | Pre-tagged by Sysmon config |

---

## Root Cause
An attacker or insider used the Frida dynamic instrumentation framework to access
the memory of a running application. Frida is a legitimate security research tool
that is frequently repurposed for credential extraction from process memory. The
randomised DLL path in AppData\Temp is consistent with Frida's runtime extraction
behaviour and indicates the tool was run without a persistent installation.

---

## Containment & Remediation

1. **Immediate:** Isolate WKSTN01 from the network to prevent lateral movement using
   any credentials extracted from memory.
2. **Short-term:** Reset passwords for all accounts that had active sessions on the
   host at the time of the event. Assume all credentials accessible in memory are
   compromised.
3. **Long-term:** Deploy Credential Guard on all endpoints to prevent userspace memory
   access to credential material. Add Frida to the EDR blocklist. Alert on any binary
   executing from AppData\Temp with randomised directory names.

---

## Lessons Learned
- Sysmon's ProcessAccess logging (EID 10) with GrantedAccess filtering is a
  high-fidelity signal that caught this with zero false positives in testing.
- Legitimate instrumentation tools (Frida, Process Hacker) require careful allowlisting
  — blocking by path pattern (AppData\Temp\[hash]) is more robust than blocking by name.
- Credential resets should be treated as mandatory after any confirmed memory access
  event, not optional.

---

## MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|---|---|---|
| Credential Access | OS Credential Dumping | T1003 |
| Defense Evasion | Masquerading (randomised path) | T1036 |

---
