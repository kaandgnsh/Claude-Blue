---
name: vendor-security-assessment
description: Assess third-party and SaaS vendor security proportionate to risk — tiering by data and access, evidence-based review (SOC 2, ISO certificates, pen test summaries, SIG/CAIQ questionnaires), external posture signals, contract security clauses, and continuous monitoring. Use when onboarding a vendor, renewing a contract, or building a third-party risk management program.
license: MIT
metadata:
  category: third-party-risk
  version: "2.0.0"
  verification: documented
---

# Vendor Security Assessment

## Tier first

| Tier | Criteria | Assessment depth |
|---|---|---|
| Critical | Processes sensitive/regulated data at scale, privileged access to our environment, critical service dependency (outage stops business) | Full: assurance reports, questionnaire, architecture call, contract clauses, annual review |
| High | Sensitive data or network/API access | Assurance report + targeted questions |
| Moderate | Limited internal data | Light questionnaire / certifications |
| Low | No data, no access | Basic due diligence |

## Evidence over questionnaires

1. **Assurance reports**: SOC 2 Type II (review per `assurance-report-review`), ISO/IEC 27001 certificate + Statement of Applicability scope, PCI AOC if card data, CSA STAR.
2. **Targeted questions** (SIG Lite/CAIQ subset) only for gaps the reports don't cover: SSO/SCIM support, MFA for vendor staff, data location, encryption & key management, sub-processors, breach notification time, backup/RTO, vulnerability management SLAs, AI/ML use of customer data.
3. **External signals**: exposed services, leaked credentials, past breaches, DMARC posture — treat security-rating scores as signals, not verdicts.
4. **Product security**: SSO with enforced MFA, audit logs available to us, admin RBAC, data export/deletion, tenant isolation, IP allow-listing.

## Contract clauses

Security requirements schedule, breach notification (e.g., ≤ 72h, ideally 24–48h), right to audit/assessment, sub-processor notification, data return/deletion at exit, insurance, vulnerability remediation SLAs, compliance with regulations (GDPR DPA Art. 28, DORA ICT third-party requirements for financial entities).

## Output

`Vendor | Tier | Data/access | Evidence reviewed | Findings | Required mitigations | Residual risk | Approver | Review date`

## Related skills

`assurance-report-review`, `third-party-access-review`, `vendor-incident-response`, `oauth-app-review`

## References

- NIST SP 800-161 Rev. 1 C-SCRM: https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final
- Shared Assessments SIG: https://sharedassessments.org/sig/
- CSA CAIQ / STAR: https://cloudsecurityalliance.org/star
- NIST CSF 2.0 GV.SC (supply chain risk management): https://www.nist.gov/cyberframework
