## Analyst Notes — T1003 OS Credential Dumping

**What the technique does:** Attackers open a handle to the LSASS (Local Security
Authority Subsystem Service) process to extract credential material — NTLM hashes,
Kerberos tickets, and cleartext passwords — from its memory. Tools like Mimikatz use
specific Windows API calls (OpenProcess, ReadProcessMemory) that Sysmon captures as
Event ID 10 with characteristic GrantedAccess bit masks.

**What we key on:** Sysmon Event ID 10 (ProcessAccess) where TargetImage is lsass.exe
and GrantedAccess matches values associated with credential dumping
(0x1010, 0x1410, 0x1fffff etc.) while filtering out known-legitimate callers.

**False positive considerations:** EDR agents, AV software, and some backup tools
legitimately access LSASS. An analyst should cross-reference SourceImage against a
known-good process list and check whether the access occurred during a scheduled
scan window before escalating.

**MITRE ATT&CK:** T1003.001 — LSASS Memory