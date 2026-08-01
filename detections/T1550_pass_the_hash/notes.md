## Analyst Notes — T1550 Pass-the-Hash

**What the technique does:** Pass-the-Hash lets an attacker authenticate to remote
systems using only a captured NTLM password hash — no plaintext password needed.
After dumping hashes from LSASS (T1003), the attacker injects the hash into a new
logon session and authenticates laterally across the network. This is why credential
dumping and lateral movement detections go together.

**What we key on:** Event ID 4624 (successful logon) with LogonType 3 (network logon)
or 9 (NewCredentials — used by tools like Mimikatz sekurlsa::pth), combined with NTLM
as the authentication package. Machine account logons (SubjectUserName ending in $)
are filtered as legitimate background noise.

**False positive considerations:** Environments still running NTLM for legacy
compatibility will produce high volumes of Event ID 4624/LogonType 3 with NTLM. Tune
by baselining which source hosts normally use NTLM and alerting only on deviation.

**MITRE ATT&CK:** T1550.002 — Pass the Hash