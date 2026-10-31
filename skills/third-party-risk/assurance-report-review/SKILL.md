---
name: assurance-report-review
description: Critically review SOC 2 Type II (and SOC 1, ISO 27001 certificates/SoA, PCI AOC) reports — scope and system description, period, carve-outs and subservice organizations, complementary user entity controls (CUECs), exceptions and qualified opinions, bridge letters. Use when evaluating a vendor's assurance report, or when a vendor offers a report as proof of security.
license: MIT
metadata:
  category: third-party-risk
  version: "2.0.0"
  verification: documented
---

# Assurance Report Review

## SOC 2 Type II checklist

| Section | What to check |
|---|---|
| Opinion (Section 1) | Unqualified vs. **qualified/adverse**; auditor firm reputation; report date |
| Period | Type II covers a period (ideally 12 months); recent (gap to today < 12 months, else request a **bridge letter**) |
| Scope / system description (Section 3) | Does the in-scope system include the product/service, regions and data you use? Trust Services Criteria covered (Security always; Availability, Confidentiality, Processing Integrity, Privacy optional) |
| Subservice organizations | Carve-out (e.g., AWS/Azure hosting excluded) → you need their reports too; inclusive method is rarer |
| CUECs | Controls **you** must operate (e.g., manage your own users, enable MFA, review access) — map to owners |
| Controls & tests (Section 4) | Relevant controls for your risks (access, change, encryption, vuln mgmt, IR, backup); test procedures meaningful (inquiry-only tests are weak) |
| Exceptions | Number, nature, management response; repeated or access/change exceptions are significant |

## ISO/IEC 27001

Certificate validity dates and accreditation body; **scope statement** (often narrow — one office or product); Statement of Applicability exclusions; surveillance audit status. A certificate says an ISMS exists for the scope — not that every control is strong.

## PCI DSS AOC

Service provider AOC level, services covered, date, requirements marked "not applicable"/"not tested", responsibility matrix (who does which requirement).

## Output

```
Vendor <> | Report type/period | Opinion | Scope covers our use: yes/partial/no
Carve-outs: <> (reports obtained: y/n)
Exceptions: <list + impact>
CUECs: <list → our control owners>
Gaps requiring follow-up questions: <>
Conclusion: acceptable / acceptable with conditions / not acceptable
```

## Related skills

`vendor-security-assessment`, `third-party-access-review`, `audit-evidence-package`

## References

- AICPA SOC 2 resources: https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2
- AICPA Trust Services Criteria: https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022
- PCI SSC AOC templates: https://www.pcisecuritystandards.org/document_library/
