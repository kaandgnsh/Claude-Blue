---
name: privacy-incident-assessment
description: Assess a personal data breach for notification obligations — GDPR Art. 33/34 (72 hours, high risk to individuals), US state breach laws, HIPAA, sector and contractual duties — by establishing facts, risk to individuals, and documentation for the DPO/legal decision. Use when personal data may have been accessed, disclosed, altered, lost or made unavailable, including ransomware and misdirected emails.
license: MIT
metadata:
  category: privacy-engineering
  version: "2.0.0"
  verification: documented
---

# Privacy Incident Assessment

Security teams supply facts; legal/DPO decides notifications. Start the clock tracking immediately: GDPR's 72 hours run from when the controller becomes **aware** (reasonable certainty that a breach occurred).

## Facts to establish

| Item | Detail |
|---|---|
| Breach type | Confidentiality (unauthorized access/disclosure), integrity (alteration), availability (loss/encryption — ransomware counts) |
| Data categories | Identifiers, contact, financial, credentials, government IDs, health, biometric, children's data, special categories (GDPR Art. 9), criminal data |
| Volume | Records and unique individuals; jurisdictions of residence |
| Role | Controller or processor (processor must notify controller "without undue delay") |
| Cause and status | Contained? Data recovered/deleted by recipient? Encryption (keys not compromised)? |
| Likely consequences | Identity theft, fraud, discrimination, reputational damage, physical harm, loss of confidentiality of professional secrecy |

## Risk assessment (EDPB approach)

Severity × likelihood considering: type and sensitivity of data, ease of identification, severity of consequences, special characteristics of individuals (vulnerable), number affected, special characteristics of the controller. Mitigations (strong encryption with uncompromised keys, confirmed deletion by a trusted recipient) can lower risk.

- **Risk** → notify supervisory authority within 72h (Art. 33), phased if facts are incomplete.
- **High risk** → also notify individuals without undue delay (Art. 34), in clear language with advice.
- **Unlikely to result in risk** → document internally (Art. 33(5) — all breaches must be recorded).

## Other regimes (check with counsel)

US state laws (definitions of personal information, AG notifications, timelines e.g. 30–60 days in many states), HIPAA Breach Notification Rule (60 days, HHS + media if > 500), SEC 8-K for material incidents (public companies), NIS2/DORA incident reporting (for in-scope entities), contractual notice to customers (often 24–72h).

## Output (for DPO/legal)

```
Incident <id> — awareness time <UTC>
Type: C/I/A   Data: <categories>   Individuals: <n> (<jurisdictions>)   Records: <n>
Cause: <>   Containment: <>   Mitigations: <encryption/deletion confirmations>
Risk assessment: <low/risk/high> because <factors>
Proposed: authority notification yes/no (deadline <>), individuals yes/no, other regimes <>
Evidence references: <case links>
```

## Related skills

`data-exposure-investigation`, `escalation-decision`, `privacy-preserving-ir`, `incident-report-writing`

## References

- GDPR Art. 33: https://gdpr-info.eu/art-33-gdpr/ ; Art. 34: https://gdpr-info.eu/art-34-gdpr/
- EDPB Guidelines 9/2022 on personal data breach notification: https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-92022-personal-data-breach-notification-under_en
- EDPB Guidelines 01/2021 examples of breach notification: https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-012021-examples-regarding-personal-data-breach_en
- HHS HIPAA Breach Notification Rule: https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html
