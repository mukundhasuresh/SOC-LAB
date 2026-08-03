## Detection Evidence — T1558 Credential Access (Kerberos Pre-Auth Failure)

**Rule:** sigma_rule.yml — Kerberos Pre-Authentication Failure
**Dataset:** datasets_raw/T1558_kerberoasting.evtx (sbousseaden/EVTX-ATTACK-SAMPLES)
**Tool:** Zircolite + Sigma
**Result:** ✅ 2 alerts fired

### Alert Output

```json
{
  "title": "Kerberos Pre-Authentication Failure — Possible Password Spray or Brute Force",
  "rule_level": "medium",
  "tags": ["attack.credential_access", "attack.t1558"],
  "count": 2,
  "matches": [
    {
      "EventID": 4771,
      "Computer": "DC01.corp.local",
      "SystemTime": "2020-07-22T20:29:36.425365Z",
      "TargetUserName": "Administrator",
      "ServiceName": "krbtgt/CORP.LOCAL",
      "Status": "0x18",
      "TicketOptions": "0x10",
      "IpAddress": "172.16.66.1",
      "Channel": "Security"
    },
    {
      "EventID": 4771,
      "Computer": "DC01.corp.local",
      "SystemTime": "2020-07-22T20:29:36.425838Z",
      "TargetUserName": "backdoor",
      "ServiceName": "krbtgt/CORP.LOCAL",
      "Status": "0x18",
      "TicketOptions": "0x10",
      "IpAddress": "172.16.66.1",
      "Channel": "Security"
    }
  ]
}
```

### Detection Logic
Two consecutive Kerberos pre-authentication failures (EID 4771, Status 0x18 = wrong
password) from the same source IP (172.16.66.1) targeting different accounts
(Administrator, backdoor) within milliseconds of each other. Classic password spray
pattern — single source, multiple targets, rapid succession.

### Analyst Verdict
**TRUE POSITIVE** — Password spray from 172.16.66.1 targeting privileged accounts on
the domain controller. The account name "backdoor" indicates a previously compromised
account being tested. An analyst would immediately block the source IP, check for
successful logons from the same source (EID 4624), and initiate account review.
