---
name: insider-risk-program
description: Establish or assess an insider risk management program — governance with HR/legal/privacy, policies and employee notice, risk indicators and tooling (Purview IRM, UEBA, DLP), case management workflow, privacy safeguards, prevention measures and metrics. Use when building an insider risk capability, evaluating insider risk tooling, or reviewing an existing program's fairness and effectiveness.
license: MIT
metadata:
  category: insider-risk
  version: "2.0.0"
  verification: documented
---

# Insider Risk Program

## Components

| Component | Content |
|---|---|
| Governance | Executive sponsor; working group (security, HR, legal, privacy, compliance, business); charter defining scope and limits |
| Policy & notice | Acceptable use, monitoring notice to employees, consequences, reporting channels (including anonymous) |
| Indicators | Technical (bulk data movement, access outside role, policy-violating uploads, privilege misuse) and HR (resignation notice, disciplinary actions) combined only within the agreed process |
| Tooling | Microsoft Purview Insider Risk Management, UEBA in SIEM, DLP, CASB, EDR — with pseudonymization of users in triage views until escalation |
| Case workflow | Triage → assessment → investigation (`insider-threat-investigation`) → outcome by HR/legal; documented decisions |
| Prevention | Least privilege, access reviews, JML (`joiner-mover-leaver`), data classification, positive culture and support channels (employee assistance) |
| Privacy & fairness | DPIA (`dpia`), proportionality, bias checks (avoid targeting protected groups), access logging of investigators |
| Metrics | Cases opened/closed, time to triage, substantiated rate, data recovered, false-positive rate, prevention actions completed |

## Maturity checks

- Is there a defined trigger for HR-security information sharing (e.g., resignation in high-risk role → enhanced monitoring for 30 days)?
- Are analysts working pseudonymized alerts first?
- Are outcomes reviewed for consistency (same behaviour → same treatment)?
- Is the program measured on prevention, not just detection?

## Related skills

`insider-threat-investigation`, `departing-employee-review`, `dpia`, `privacy-preserving-ir`

## References

- CISA Insider Threat Mitigation Guide: https://www.cisa.gov/resources-tools/resources/insider-threat-mitigation-guide
- CERT National Insider Threat Center: https://insights.sei.cmu.edu/insider-threat/
- Microsoft Purview Insider Risk Management: https://learn.microsoft.com/en-us/purview/insider-risk-management
