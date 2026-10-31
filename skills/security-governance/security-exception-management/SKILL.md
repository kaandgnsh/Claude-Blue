---
name: security-exception-management
description: Run a security exception (policy waiver) process — intake, risk evaluation, compensating controls, approval authority by risk level, time limits, tracking, renewal and reporting — and audit existing exceptions. Use when someone cannot meet a security policy or standard, when designing the exception process, or reviewing an exception backlog.
license: MIT
metadata:
  category: security-governance
  version: "2.0.0"
  verification: documented
---

# Security Exception Management

## Process

1. **Request**: requirement not met (policy/standard ID), scope (systems, users), reason, business impact of compliance, proposed compensating controls, requested duration, remediation plan.
2. **Assess**: security evaluates risk with and without compensating controls; verifies controls exist (evidence) — e.g., network isolation rule IDs, monitoring detection IDs.
3. **Approve** by risk level:
   | Residual risk | Approver | Max duration |
   |---|---|---|
   | Low | Security manager | 12 months |
   | Medium | CISO / system owner's director | 6 months |
   | High | Executive risk owner (CIO/COO) | 90 days |
   | Critical | Not approvable except by executive committee with remediation commitment | 30 days |
4. **Record** in a register (GRC tool / ticket system) with expiry, owner, conditions.
5. **Monitor**: alerts before expiry, auto-escalation on expiry, periodic verification of compensating controls.
6. **Close**: remediated, renewed (with re-assessment), or escalated.

## Register audit

Flag expired-but-active exceptions, missing approvals, controls not verifiable, perpetual renewals (> 2 renewals = systemic issue → risk register entry), exceptions for decommissioned assets, many exceptions on one standard (the standard may be unrealistic — review it).

## Reporting

Count by risk level and age, top requesting teams, standards with most exceptions, expired count — reported quarterly to governance forum.

## Request template

```
Exception request <id>
Requirement: <policy/standard ID and text>
Scope: <assets/users/apps>   Requested until: <date>
Reason: <why compliance isn't possible now; evidence>
Risk if not compliant: <threat scenario>
Compensating controls: <control → evidence (rule IDs, configs)>
Remediation plan: <action, owner, date>
Business owner: <name/role>   Security assessment: <residual risk>
Decision: <approved/rejected/conditions>   Approver: <>   Date: <>
```

## Related skills

`vuln-exception-review`, `risk-register`, `policy-review`

## References

- NIST SP 800-53 Rev. 5 PM-9 Risk Management Strategy / CA-5 Plan of Action and Milestones: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- ISO/IEC 27001:2022 clause 6.1.3 risk treatment (standard; purchase required)
