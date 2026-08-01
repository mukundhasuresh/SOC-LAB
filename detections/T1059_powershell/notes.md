## Analyst Notes — T1059 Suspicious PowerShell

**What the technique does:** Attackers use PowerShell's -EncodedCommand flag to pass
Base64-encoded scripts that bypass basic keyword-based defenses and avoid leaving
readable script content on disk. Encoded payloads are a standard delivery mechanism
for downloaders, reverse shells, and post-exploitation frameworks like Empire and
Cobalt Strike.

**What we key on:** Sysmon Event ID 1 (ProcessCreate) where powershell.exe or pwsh.exe
is launched with encoded command flags (-enc, -ec, -EncodedCommand). We filter SCCM
as a known legitimate user of this pattern to reduce deployment-tool noise.

**False positive considerations:** SCCM and some enterprise deployment tools
legitimately encode PowerShell payloads for delivery. Tune by adding ParentImage
exclusions for known software management tools in your environment.

**MITRE ATT&CK:** T1059.001 — PowerShell