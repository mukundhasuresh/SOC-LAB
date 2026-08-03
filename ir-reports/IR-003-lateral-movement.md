# IR-003 — Lateral Movement via PsExec Named Pipe (SMB)
**Severity:** High
**Status:** Closed (Simulated)
**ATT&CK Technique:** T1021.002 — Remote Services: SMB/Windows Admin Shares
**Detection Source:** Sigma rule — PsExec Named Pipe Creation (Sysmon EID 18)
**Date:** 2019-04-30

---

## Summary
Sysmon detected the creation of the named pipe `\ntsvcs` on WKSTN02 — the pipe used
by PsExec for communication between the attacker and the remote service it installs.
This is a reliable, low-noise indicator of PsExec-based lateral movement. The pipe
was created by the System process, confirming WKSTN02 is the target (victim) host,
not the source of the attack.

---

## Detection Timeline

| Time (UTC) | Event |
|---|---|
| 2019-04-30 20:26:51 | Sysmon EID 18 fires — named pipe \ntsvcs created on WKSTN02 |
| 2019-04-30 20:26:51 | Sigma rule matches — PsExec pipe name detected |
| T+3 min | Alert reviewed — no authorised remote admin scheduled for this host |
| T+8 min | WKSTN02 isolated from network |
| T+15 min | Source of PsExec connection identified via EID 3 network events |
| T+30 min | PSEXESVC.exe artifact located and removed from WKSTN02 |
| T+45 min | Full scope assessment — checked all hosts for same pipe name in same window |

---

## Indicators of Compromise

| Type | Value | Significance |
|---|---|---|
| EventID | 18 (Sysmon PipeEvent) | Named pipe connection detected |
| PipeName | \ntsvcs | PsExec's default communication pipe |
| Image | System | Target-side service process — confirms victim role |
| Host | WKSTN02 | Lateral movement destination |
| Artifact on disk | PSEXESVC.exe | PsExec drops this on the target |

---

## Root Cause
An attacker with valid credentials (likely obtained via earlier credential dumping —
see IR-001) used PsExec or a PsExec-compatible tool (Impacket psexec.py, Cobalt
Strike's PsExec module) to move laterally to WKSTN02. PsExec copies its service
binary (PSEXESVC.exe) to the target over SMB, creates a Windows service, and
communicates via the \ntsvcs named pipe. The System process creating the pipe
confirms the service was successfully installed and executing on the target.

---

## Containment & Remediation

1. **Immediate:** Isolate WKSTN02. The attacker had SYSTEM-level access from the
   moment the pipe was established — assume full host compromise.
2. **Short-term:** Identify the source host by correlating EID 3 (network connection)
   events on WKSTN02 in the same 5-second window as the pipe creation. Isolate source
   host as well. Locate and delete PSEXESVC.exe from WKSTN02\Admin$.
3. **Long-term:** Block inbound SMB (port 445) between workstations at the firewall
   level — workstation-to-workstation SMB has very few legitimate use cases and is a
   primary lateral movement path. Deploy host-based firewall rules via GPO. Alert on
   PSEXESVC.exe process creation (Sysmon EID 1) on any non-server host.

---

## Lessons Learned
- Named pipe detection (Sysmon EID 17/18) is an underused but highly reliable lateral
  movement signal. The \ntsvcs pipe name has not changed across PsExec versions,
  making it a stable, low-maintenance detection.
- IR-001 (credential access) and IR-003 (lateral movement) are linked — the likely
  attack chain is: credential dump → Pass-the-Hash → PsExec lateral movement. Chaining
  alerts across techniques reveals attacker kill chain progression that individual
  alerts miss.
- Scope assessment (checking all hosts for the same pipe in the same timeframe) is
  critical — PsExec lateral movement is rarely a single hop.

---

## MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|---|---|---|
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Execution | System Services: Service Execution | T1569.002 |
| Credential Access | OS Credential Dumping (linked — IR-001) | T1003 |
