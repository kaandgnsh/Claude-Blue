---
name: incident-report-writing
description: Write incident reports for different audiences — executive summary, technical report, regulator/customer notification draft — with consistent facts, confidence language and impact statements. Use when an incident needs a written report for leadership, legal, auditors, customers or regulators.
license: MIT
metadata:
  category: incident-response
  version: "2.0.0"
  verification: documented
---

# Incident Report Writing

One fact base, several audiences. Write the technical report first; derive the others from it so numbers and dates never disagree.

## Audience matrix

| Audience | Length | Contains | Avoids |
|---|---|---|---|
| Executive / board | 1 page | What happened, business impact, status, decisions needed, cost/risk | Tool names, IOCs, jargon |
| Technical | As needed | Timeline, scope, TTPs (ATT&CK), evidence, root cause, remediation, IOCs | Speculation without labels |
| Regulator/customer (draft for counsel) | Per legal | Nature of incident, data categories, approximate numbers, measures taken, contact point | Unverified claims, admissions not approved by counsel |

## Writing rules

- Lead with the conclusion (BLUF).
- Dates in UTC with timezone; quantities with confidence ("approximately 4,200 records, confirmed").
- Consistent confidence words: confirmed / likely / possible / not observed (with telemetry coverage).
- Distinguish *accessed*, *exfiltrated*, and *exposed*.
- Every technical claim maps to evidence in the case file.
- Mark privilege as directed by counsel (e.g., "Privileged & Confidential — prepared at the direction of counsel").

## Executive summary template

```
What happened: <2 sentences>
Impact: <systems, data, customers, operations, $ if known>
Current status: <contained/recovering/monitoring>
Root cause: <one line>
What we're doing: <3 bullets>
Decisions/support needed: <>
Next update: <date>
```

## Technical report outline

1. Executive summary  2. Scope and methodology  3. Timeline  4. Initial access  5. Attacker actions mapped to ATT&CK  6. Impact (systems/data)  7. Containment, eradication, recovery  8. Root cause & contributing factors  9. Recommendations  10. Appendices: IOCs, queries, evidence inventory

## Related skills

`forensic-report`, `after-action`, `case-documentation`, `privacy-incident-assessment`

## References

- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- MITRE ATT&CK: https://attack.mitre.org/
