## Analyst Notes — T1021 Lateral Movement (PsExec/SMB)

**What the technique does:** PsExec (and PsExec-like tools built into Cobalt Strike,
Metasploit, and Impacket) copy a service binary to the target machine over SMB and
create a Windows service to execute it. This gives the attacker SYSTEM-level access
on the remote host. The PSEXESVC.exe binary appearing on a host it was never deployed
to is a strong indicator of compromise.

**What we key on:** Sysmon Event ID 1 (ProcessCreate) with Image ending in PSEXESVC.exe
(the service binary PsExec drops), and/or Event ID 13 (RegistryValueSet) where a
PSEXESVC service key is written under CurrentControlSet\Services. Either signal is
high-confidence — both together is near-certain.

**False positive considerations:** IT teams sometimes legitimately use PsExec for
remote administration. An analyst should verify the source host, the account used,
and whether this aligns with a known change window or helpdesk ticket before treating
this as malicious.

**MITRE ATT&CK:** T1021.002 — SMB/Windows Admin Shares