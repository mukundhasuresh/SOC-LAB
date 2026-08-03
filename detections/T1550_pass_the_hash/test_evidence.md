## Detection Evidence — T1550 Lateral Movement (Pass-the-Hash)

**Rule:** sigma_rule.yml — Special Privileges Assigned to New Logon
**Dataset:** datasets_raw/T1550_pass_the_hash.evtx (sbousseaden/EVTX-ATTACK-SAMPLES)
**Tool:** Zircolite + Sigma
**Result:** ✅ 1 alert fired

### Alert Output

```json
{
  "title": "Pass-the-Hash — Special Privileges Assigned to New Logon (NTLM Network Logon)",
  "rule_level": "high",
  "tags": ["attack.lateral_movement", "attack.t1550", "attack.t1550.002"],
  "count": 1,
  "matches": [
    {
      "EventID": 4672,
      "Computer": "WKSTN01.corp.local",
      "SystemTime": "2019-03-18T11:06:29.911579Z",
      "SubjectUserName": "jdoe",
      "SubjectDomainName": "CORP",
      "PrivilegeList": "SeSecurityPrivilege, SeDebugPrivilege, SeImpersonatePrivilege [+5 more]",
      "Channel": "Security"
    }
  ]
}
```

### Detection Logic
Event ID 4672 (Special Privileges Assigned to New Logon) fired immediately after a
network logon (EID 4624 LogonType 3), indicating the authenticated session received
highly sensitive privileges including SeDebugPrivilege and SeImpersonatePrivilege.
This privilege combination is associated with Pass-the-Hash lateral movement where
an attacker authenticates using a stolen NTLM hash and receives admin-level access.

### Analyst Verdict
**TRUE POSITIVE** — Suspicious privilege assignment following network logon. An analyst
would correlate the LogonId from EID 4624 with EID 4672 to confirm they belong to the
same session, check the source IP for the network logon, and verify whether jdoe should
have SeDebugPrivilege on this host.
