## Analyst Notes — T1055 Process Injection

**What the technique does:** Process injection allows an attacker to run malicious
code inside a legitimate, trusted process. This hides the attacker's activity from
process-based defenses (the malicious code appears to belong to e.g. explorer.exe
or svchost.exe) and can inherit elevated privileges from the target process.
CreateRemoteThread is one of the most common injection primitives — used by Metasploit,
Cobalt Strike, and many other frameworks.

**What we key on:** Sysmon Event ID 8 (CreateRemoteThread) where a non-system process
creates a thread in another process. We filter known-legitimate callers (csrss, wininit,
svchost in their System32 paths) to reduce noise from Windows itself.

**False positive considerations:** AV and EDR products, .NET JIT compilation, and
some legitimate instrumentation tools create remote threads. Validate SourceImage
against a known software inventory before escalating.

**MITRE ATT&CK:** T1055 — Process Injection