## Analyst Notes — T1558 Kerberoasting

**What the technique does:** Kerberoasting abuses the Kerberos protocol. Any
authenticated domain user can request a service ticket (TGS) for any account with
a Service Principal Name (SPN). The ticket is encrypted with the service account's
NTLM hash, which the attacker can take offline and crack. High-privilege service
accounts with weak passwords are the primary target.

**What we key on:** Windows Security Event ID 4769 (Kerberos Service Ticket Request)
where TicketEncryptionType is 0x17 (RC4-HMAC — weak, attacker-preferred) and
TicketOptions is 0x40810000 (forwardable renewable ticket flags). We filter out
machine accounts (ending in $) since those generate legitimate RC4 requests.

**False positive considerations:** Legacy applications and old systems that cannot
use AES Kerberos encryption will trigger this. An analyst should check whether the
ServiceName is a known legacy application service account before escalating.

**MITRE ATT&CK:** T1558.003 — Kerberoasting