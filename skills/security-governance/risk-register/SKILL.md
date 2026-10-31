---
name: risk-register
description: Build and maintain a cybersecurity risk register — risk statements (threat, vulnerability, asset, impact), inherent and residual ratings, treatment decisions, owners, key risk indicators and review cadence — aligned with NIST CSF 2.0 Govern, ISO/IEC 27005 and enterprise risk management. Use when creating or auditing a risk register, translating findings into risks, or preparing risk reporting for leadership.
license: MIT
metadata:
  category: security-governance
  version: "2.0.0"
  verification: documented
---

# Cybersecurity Risk Register

## Write a proper risk statement

"**[Threat]** could exploit **[vulnerability/condition]** in **[asset/process]**, resulting in **[business impact]**."
Example: "Ransomware operators could exploit internet-exposed VPN appliances without timely patching to access the corporate network, resulting in multi-day outage of order processing and data-theft extortion."

A finding ("VPN patch missing") is not a risk; many findings roll up to one risk.

## Register fields

| Field | Notes |
|---|---|
| ID, title, statement | As above |
| Category | e.g., CSF 2.0 function / ERM taxonomy |
| Asset/process & owner | Business owner accepts risk, not IT |
| Inherent likelihood × impact | Organization's scale (e.g., 1–5) with defined criteria (financial bands, downtime hours, regulatory) |
| Existing controls | Specific, with effectiveness evidence |
| Residual rating | After controls |
| Treatment | Mitigate / transfer (insurance, contract) / avoid / accept |
| Plan & due date | Linked tickets |
| KRIs | Measurable indicators (patch latency for edge devices, % phishing-resistant MFA) |
| Appetite comparison | Within/outside appetite |
| Review date | Quarterly for high risks |

Quantitative option for top risks: FAIR (`risk-quantification-fair`).

## Workflow

1. Gather inputs: threat intel/profile, incidents, assessments, audit findings, vulnerability trends, business changes.
2. Draft risks with owners in workshops; avoid > 30–50 active top-level risks.
3. Rate consistently (calibration across raters); document rationale.
4. Decide treatment with owners; acceptance above thresholds needs executive sign-off.
5. Report: heat map + trend, top risks outside appetite, overdue treatments, KRIs breaching thresholds.

## Related skills

`risk-quantification-fair`, `maturity-assessment`, `security-exception-management`, `security-metric-definition`

## References

- NIST CSF 2.0: https://www.nist.gov/cyberframework
- NIST IR 8286 series (integrating cybersecurity and ERM): https://csrc.nist.gov/pubs/ir/8286/r1/final
- ISO/IEC 27005:2022 information security risk management (standard; purchase required)
