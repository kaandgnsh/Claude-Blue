---
name: dpia
description: Conduct a Data Protection Impact Assessment (GDPR Art. 35) or privacy impact assessment — screening criteria, data flow description, necessity and proportionality, risks to individuals (LINDDUN), mitigations, DPO consultation and residual risk sign-off. Use when launching processing likely to be high risk (monitoring, large-scale sensitive data, profiling, new technology including AI), or when asked whether a DPIA is required.
license: MIT
metadata:
  category: privacy-engineering
  version: "2.0.0"
  verification: documented
---

# Data Protection Impact Assessment

## Is a DPIA required? (screening)

GDPR Art. 35(3) mandatory cases: systematic and extensive profiling with significant effects; large-scale special-category or criminal data; systematic monitoring of public areas. EDPB (WP248) criteria — two or more usually means DPIA: evaluation/scoring, automated decisions with legal effect, systematic monitoring, sensitive data, large scale, matching/combining datasets, vulnerable data subjects (employees, children), innovative technology (e.g. AI, biometrics), preventing exercise of rights. Check your supervisory authority's published list.

## Contents

1. **Description**: purposes, data categories, data subjects, sources, recipients/processors, transfers outside EEA, retention, systems (data-flow diagram).
2. **Necessity & proportionality**: lawful basis (Art. 6, Art. 9 condition), data minimization, accuracy, retention, transparency, rights handling, processor contracts (Art. 28), transfer safeguards.
3. **Risks to individuals** (not the company): illegitimate access, unwanted modification, disappearance; plus privacy threats from LINDDUN — Linkability, Identifiability, Non-repudiation, Detectability, Disclosure, Unawareness, Non-compliance. Rate likelihood and severity.
4. **Measures**: pseudonymization, encryption, access control, aggregation, purpose restriction controls, retention automation, user controls, transparency notices, human review of automated decisions.
5. **Residual risk & sign-off**: DPO advice recorded; if high residual risk remains → prior consultation with the supervisory authority (Art. 36).
6. **Review trigger**: change of purpose, new data, new technology, incidents.

## Security team contribution

Threat model (`threat-modeling`), access and logging design, encryption/key management, retention enforcement, breach detection capability, vendor security assessment for processors.

## Output

`Risk | Source (LINDDUN/security) | Likelihood | Severity | Measure | Owner | Residual risk`

## Related skills

`threat-modeling`, `telemetry-minimization`, `data-classification`, `vendor-security-assessment`

## References

- GDPR Art. 35: https://gdpr-info.eu/art-35-gdpr/
- WP248 rev.01 DPIA guidelines (endorsed by EDPB): https://ec.europa.eu/newsroom/article29/items/611236
- ICO DPIA guidance: https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/accountability-and-governance/data-protection-impact-assessments-dpias/
- LINDDUN: https://linddun.org/
