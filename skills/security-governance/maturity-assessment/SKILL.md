---
name: maturity-assessment
description: Assess security program maturity against NIST CSF 2.0 (organizational profiles and tiers), CIS Controls v8.1 implementation groups, or C2M2 — evidence-based current vs. target profiles, gap prioritization and a funded roadmap. Use for annual program assessments, board reporting, after a new CISO starts, or to prioritize security investment.
license: MIT
metadata:
  category: security-governance
  version: "2.0.0"
  verification: documented
---

# Security Maturity Assessment

## Choose the frame

| Framework | Use when |
|---|---|
| NIST CSF 2.0 (Govern, Identify, Protect, Detect, Respond, Recover; tiers 1–4; Current/Target Profiles) | Enterprise-wide outcome view, board reporting |
| CIS Controls v8.1 (18 controls, IG1/IG2/IG3 safeguards) | Prescriptive technical baseline, smaller orgs |
| C2M2 | Energy/OT and critical infrastructure |
| ISO/IEC 27001 | Certification-oriented ISMS |

## Method

1. **Scope** business units and environments.
2. **Collect evidence** per subcategory/safeguard: documents, configuration exports, metrics (coverage %, SLAs), interviews, sampling. Score on evidence, not self-reporting.
3. **Score**: e.g., 0 not implemented / 1 partial / 2 implemented in parts / 3 implemented and measured / 4 optimized; or CSF tiers for governance aspects.
4. **Set target profile** from risk appetite, threat profile, regulatory needs — not everything must be "4".
5. **Prioritize gaps** by risk reduction per cost; tie to top risks (`risk-register`).
6. **Roadmap**: 3–4 quarters of initiatives with owners, budget, success metrics.

## Evidence examples

- PR.AA (Identity Management, Authentication, Access Control): % accounts with phishing-resistant MFA, access review completion.
- DE.CM (Continuous Monitoring): EDR coverage, log source coverage vs. inventory.
- RS.MA (Incident Management): tabletop dates, IR plan currency, MTTD/MTTR.
- RC.RP (Incident Recovery Plan Execution): restore test results, RTO met?
- GV.SC (Cybersecurity Supply Chain Risk Management): vendor tiering and assessment coverage.

## Output

`Function/Category | Subcategory | Current score | Evidence | Target | Gap | Initiative | Priority`
+ one-page summary: strengths, top 5 gaps, roadmap.

## Related skills

`risk-register`, `control-mapping`, `security-metric-definition`, `zero-trust-assessment`

## References

- NIST CSF 2.0 and resources (profiles, informative references): https://www.nist.gov/cyberframework
- CIS Controls v8.1: https://www.cisecurity.org/controls
- C2M2: https://www.energy.gov/ceser/cybersecurity-capability-maturity-model-c2m2
