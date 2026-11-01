---
name: security-test-planning
description: Write the plan and rules of engagement for a security test (penetration test, red team, purple team, BAS rollout, control validation) covering objectives, scope and exclusions, authorization, test windows, deconfliction, stop conditions, data handling, communication and reporting. Use when commissioning or preparing a security test, reviewing a vendor's test proposal, or when a test needs written authorization before it starts.
license: MIT
metadata:
  category: security-testing
  version: "2.2.0"
  verification: documented
---

# Security Test Planning

The plan is what makes an attack a test. It protects the testers legally, protects production operationally, and makes the result useful. No signed plan, no testing.

## 1. Choose the test type for the question

| Question | Test type | Typical duration |
|---|---|---|
| Are known weaknesses present in this app/network? | Penetration test (scoped, overt to IT) | 1-3 weeks |
| Would we detect and stop a realistic attacker end to end? | Red team (objective-based, covert to SOC) | 4-12 weeks |
| Which techniques do we see, and can we fix gaps fast? | Purple team (collaborative) | 1-5 days |
| Do our controls still work after every change? | BAS / automated control validation | Continuous |
| Does a specific control operate as designed? | Control validation | Hours-days |

## 2. Plan contents

1. **Objectives**: 2-5 measurable goals (e.g., "obtain read access to the payroll database from a standard user workstation"; "determine whether the SOC detects credential dumping on Tier 1 servers").
2. **Scope**: in-scope assets by identifier (CIDRs, hostnames, app URLs, cloud subscription IDs, tenants), accounts provided, techniques allowed.
3. **Exclusions**: assets, techniques and times that are off-limits (production databases writes, DoS, physical access, social engineering of named executives, third-party SaaS without the provider's permission).
4. **Authorization**: signed by someone with authority over every in-scope asset; cloud provider and SaaS testing policies checked; third parties notified where contracts require it.
5. **Windows**: dates, hours, timezone; blackout periods (month-end close, releases).
6. **Deconfliction**: a named trusted agent in the SOC (red team) or a shared channel (purple), test source IPs and accounts, a code word to confirm "is this you?" within 15 minutes, 24/7.
7. **Stop conditions**: production instability, discovery of a real intrusion or prior compromise, access to out-of-scope data (e.g., health records), legal or safety concerns. Who may call stop, and how testing resumes.
8. **Data handling**: no exfiltration of real sensitive data (use canary files or hashes as proof), encryption of evidence at rest, retention and destruction date, tester endpoint requirements.
9. **Communication**: daily status, immediate notification for critical findings (e.g., exposed admin interface, credentials in a public repo), contact list with deputies.
10. **Reporting**: format, severity scale, retest included or not, delivery date, distribution list.

## 3. Rules of engagement template

```markdown
# Rules of engagement: <test name>   Version: <n>   Date: <date>
Objectives: <list>
In scope: <identifiers>    Out of scope: <identifiers>
Allowed techniques: <list>  Prohibited: DoS, destructive actions, <...>
Window: <dates/times TZ>    Test source IPs: <list>   Test accounts: <list>
Deconfliction contact (24/7): <role, phone>   Code word: <shared out of band>
Stop conditions: <list>   Stop authority: <roles>
Data handling: <rules>   Evidence retention until: <date>
Critical finding notification: within <N> hours to <role>
Authorized by: <name, title, signature, date>   Tester lead: <name, signature, date>
```

## 4. Before day one

- [ ] Signatures from all asset owners, including cloud subscription owners and outsourced IT where relevant.
- [ ] Test accounts created with expiry dates; test hosts tagged in CMDB/SIEM.
- [ ] Backups verified for in-scope systems where any write action is allowed.
- [ ] SOC briefing according to test type (purple: all; red: trusted agent only).
- [ ] Legal review where employee monitoring, social engineering or third-party systems are involved.

## 5. After the test

- Remove test accounts, tools, persistence and firewall exceptions; get written confirmation (see `attack-simulation-safety`).
- Track findings to closure with owners and due dates; schedule retest.
- Feed detection gaps into `detection-validation` and the ATT&CK coverage map.

## Related skills

`attack-simulation-safety`, `purple-team-exercise`, `control-validation`, `bas-results-review`, `vendor-security-assessment`, `exposure-validation`

## References

- NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment): https://csrc.nist.gov/pubs/sp/800/115/final
- PTES technical guidelines: http://www.pentest-standard.org/
- AWS penetration testing policy: https://aws.amazon.com/security/penetration-testing/
- Microsoft Cloud penetration testing rules of engagement: https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement
- CBEST / TIBER-EU threat intelligence-based red teaming: https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html
