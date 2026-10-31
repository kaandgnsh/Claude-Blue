---
name: control-mapping
description: Build and maintain a unified control framework that maps one set of internal controls to multiple frameworks — ISO/IEC 27001:2022 Annex A, SOC 2 TSC, NIST CSF 2.0, NIST SP 800-53, PCI DSS v4.0.1, CIS Controls, HIPAA, NIS2/DORA — using official crosswalks (NIST OLIR, CSF informative references) to test once, comply many. Use when preparing for multiple audits, onboarding a new framework, or performing gap analysis.
license: MIT
metadata:
  category: compliance-audit
  version: "2.0.0"
  verification: documented
---

# Control Mapping (Unified Control Framework)

## Structure

`Internal control ID | Control statement (testable) | Owner | Frequency | Evidence | Mapped requirements (ISO A.x, SOC2 CCx.x, CSF xx.xx-xx, 800-53 xx-n, PCI x.x.x, CIS x.x)`

Example internal control:
- **IAM-03**: "Administrative access to production systems requires phishing-resistant MFA; compliance is reported monthly from the IdP."
- Maps to: ISO/IEC 27001:2022 A.8.5 (Secure authentication); SOC 2 CC6.1; NIST CSF 2.0 PR.AA-03; NIST SP 800-53 IA-2(1), IA-2(2); PCI DSS v4.0.1 8.4.2; CIS Controls 6.5.

(Verify each mapping against the current framework text — numbering changes between versions.)

## Method

1. Start from the framework with the most granular requirements you must meet (often 800-53 or PCI) or from your existing control set.
2. Use authoritative crosswalks: NIST CSF 2.0 informative references and OLIR mappings, CIS Controls mappings, ISO 27001 ↔ 27002 guidance, AICPA SOC 2 to CSF mapping.
3. Write controls as **testable statements** (who/what/how often/evidence).
4. Identify gaps: framework requirements with no mapped internal control.
5. Assign owners and evidence sources; automate evidence where possible (`continuous-control-monitoring`).
6. Version the mapping; update on framework revisions (e.g., PCI DSS v4.0 future-dated requirements effective 31 March 2025).

## Gap analysis output

`Framework requirement | Mapped control(s) | Coverage (full/partial/none) | Gap | Action | Owner`

## Related skills

`audit-evidence-package`, `continuous-control-monitoring`, `maturity-assessment`, `policy-review`

## References

- NIST CSF 2.0 informative references: https://www.nist.gov/informative-references
- NIST OLIR program: https://csrc.nist.gov/projects/olir
- CIS Controls mappings: https://www.cisecurity.org/controls/cis-controls-navigator
- PCI DSS v4.0.1 document library: https://www.pcisecuritystandards.org/document_library/
- AICPA Trust Services Criteria: https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022
