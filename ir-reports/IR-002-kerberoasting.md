# IR-002 — Kerberos Password Spray Against Domain Controller
**Severity:** Medium → High (escalated on account targeting)
**Status:** Closed (Simulated)
**ATT&CK Technique:** T1558 — Steal or Forge Kerberos Tickets
**Detection Source:** Sigma rule — Kerberos Pre-Auth Failure EID 4771
**Date:** 2020-07-22

---

## Summary
Two rapid Kerberos pre-authentication failures (EID 4771, Status 0x18) were detected
from the same source IP (172.16.66.1) against the domain controller within milliseconds
of each other. Targets included the built-in Administrator account and an account named
"backdoor" — indicating either account enumeration or a targeted spray against known
or previously created accounts.

---

## Detection Timeline

| Time (UTC) | Event |
|---|---|
| 2020-07-22 20:29:36.425 | EID 4771 fires — Administrator pre-auth failure from 172.16.66.1 |
| 2020-07-22 20:29:36.425 | EID 4771 fires — "backdoor" account pre-auth failure, same source |
| 2020-07-22 20:29:36 | Sigma rule matches — 2 alerts, same IP, millisecond gap |
| T+2 min | Source IP reviewed — no authorised admin activity expected |
| T+10 min | Source host identified and isolated |
| T+20 min | Full account audit initiated on DC01.corp.local |

---

## Indicators of Compromise

| Type | Value | Significance |
|---|---|---|
| EventID | 4771 | Kerberos pre-auth failure |
| Status | 0x18 | Wrong password supplied |
| Source IP | 172.16.66.1 | Single source, multiple targets |
| Target accounts | Administrator, backdoor | Privileged + suspicious account names |
| Time gap between failures | <1ms | Automated tool, not human typing |
| ServiceName | krbtgt/CORP.LOCAL | Targeting the domain TGT service |

---

## Root Cause
An automated credential attack tool executed a password spray against the domain
controller from an internal host (172.16.66.1). The sub-millisecond gap between
authentication attempts confirms automated tooling rather than manual login attempts.
The presence of an account named "backdoor" as a target suggests prior attacker
knowledge of the environment — possibly from earlier reconnaissance or a previously
planted account being tested.

---

## Containment & Remediation

1. **Immediate:** Block 172.16.66.1 at the network level. Investigate what host owns
   this IP and whether it has been compromised.
2. **Short-term:** Audit the "backdoor" account — determine when it was created, by
   whom, and disable it immediately if origin is unclear. Review all accounts for
   suspicious creation timestamps.
3. **Long-term:** Enable Account Lockout Policy for domain accounts (threshold: 5
   failures). Deploy fine-grained password policies for privileged accounts. Alert on
   any source IP generating more than 3 EID 4771 events within 60 seconds.

---

## Lessons Learned
- The sub-millisecond timing between failures is the most reliable indicator of
  automated spraying — human typos don't happen that fast. Building time-window
  correlation into the detection (>3 failures per IP per minute) would reduce
  false positives further.
- The "backdoor" account name is a strong secondary indicator that should have been
  caught at account creation time — monitoring EID 4720 (account created) for
  suspicious naming patterns is a useful companion detection.

---

## MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force: Password Spraying | T1110.003 |
| Credential Access | Steal or Forge Kerberos Tickets | T1558 |
| Reconnaissance | Account Discovery | T1087 |

---
