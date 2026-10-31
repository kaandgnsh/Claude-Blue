---
name: intel-report-writing
description: Write and review threat intelligence products — strategic, operational and tactical reports — with key judgments, estimative language (ICD 203 style), source reliability, ATT&CK-mapped TTPs, IOCs, and actionable recommendations tied to intelligence requirements. Use when producing intel briefs, threat assessments or advisories, or critically reviewing a vendor threat report.
license: MIT
metadata:
  category: threat-intelligence
  version: "2.0.0"
  verification: documented
---

# Intelligence Report Writing

## Product types

| Type | Audience | Content |
|---|---|---|
| Strategic | Executives, risk | Threat landscape trends, actor intent, business risk, investment implications |
| Operational | IR/SOC leads | Campaigns targeting sector, actor TTPs, timing, what to prioritize |
| Tactical | Analysts/engineers | IOCs, detections, hunting queries, mitigations |

## Structure

1. **BLUF / key judgments** (each with confidence: low/moderate/high)
2. **Relevance**: which intelligence requirement (`intelligence-requirements`) this answers
3. **Analysis**: evidence, sources (with reliability), alternative hypotheses
4. **TTPs**: ATT&CK mapped, with procedure-level detail
5. **Implications**: exposure in *our* environment (do we run the targeted product? coverage?)
6. **Recommendations**: specific actions with owners (patch X, deploy detection Y, hunt Z)
7. **IOCs / detections** appendix (machine-readable link)
8. **Sources, TLP, date, author, distribution**

## Estimative language

Use consistent probability terms (ICD 203): almost no chance (01–05%), very unlikely (05–20%), unlikely (20–45%), roughly even chance (45–55%), likely (55–80%), very likely (80–95%), almost certain (95–99%). Separate **likelihood** of an event from **analytic confidence** in the judgment.

## Reviewing vendor reports

- Is attribution evidence presented or only asserted? Are IOCs dated?
- Which claims are first-hand (incident data) vs. reposted?
- Do TTPs include procedures detailed enough to detect?
- Does the targeted technology/sector match ours?

## Related skills

`intelligence-requirements`, `campaign-correlation`, `intel-to-detection`, `malware-report`

## References

- ODNI ICD 203 Analytic Standards: https://www.dni.gov/files/documents/ICD/ICD-203.pdf
- FIRST TLP 2.0: https://www.first.org/tlp/
- MITRE ATT&CK: https://attack.mitre.org/
