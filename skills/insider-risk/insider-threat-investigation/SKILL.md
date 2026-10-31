---
name: insider-threat-investigation
description: Investigate suspected insider threats (data theft, sabotage, fraud, policy violations) lawfully and fairly — case intake with HR/legal, proportionate evidence collection (DLP, cloud audit, endpoint, badge), timeline building, avoiding tip-off, and objective reporting. Use when an employee or contractor is suspected of misusing access, or insider-risk tooling raises a high-severity case.
license: MIT
metadata:
  category: insider-risk
  version: "2.0.0"
  verification: documented
---

# Insider Threat Investigation

## Governance first

- Open the case with **legal and HR**; define the allegation, scope, and who is informed (need-to-know; the subject's manager may not be appropriate).
- Confirm lawful basis and local rules (employee monitoring laws, works councils, union agreements, privacy notices) — see `privacy-preserving-ir`.
- Preserve evidence early (legal hold on mailbox/OneDrive/Drive, retain logs) without visible changes to the user's access unless risk requires.

## Evidence sources (metadata first)

| Source | Questions |
|---|---|
| Cloud audit (M365 UAL, Google Drive, Box) | Bulk downloads, syncing to personal devices, sharing to personal accounts, anonymous links (`m365-audit-investigation`) |
| Email | Forwarding to personal addresses, large attachments outbound |
| DLP / CASB | Policy matches, uploads to personal cloud storage, GenAI tools |
| Endpoint (EDR/DLP) | USB mass storage writes, archive creation (7z/rar), printing, screenshots tools, cloud sync clients |
| Source control | Unusual clones/downloads (`github-audit-investigation`) |
| Identity | Off-hours logins, new devices, access to systems outside role |
| Physical | Badge records (with HR/legal approval) |

## Method

1. Baseline the user's normal behaviour (same role peers, previous 90 days).
2. Build a timeline correlating HR context (resignation notice date, performance issues) with technical events — these indicate motive/opportunity, not proof.
3. Quantify data involved (files, classification, volume) and destinations.
4. Consider innocent explanations (backup of personal files, assigned project work) and test them against evidence.
5. Report facts with confidence levels; decisions (interview, termination, legal action) belong to HR/legal.

## Do not

Confront the subject, change their access visibly, or discuss the case outside the case team without legal direction; never access personal content beyond approved scope.

## Related skills

`departing-employee-review`, `insider-risk-program`, `privacy-preserving-ir`, `dlp-alert-triage`

## References

- CISA Insider Threat Mitigation Guide: https://www.cisa.gov/resources-tools/resources/insider-threat-mitigation-guide
- CERT Common Sense Guide to Mitigating Insider Threats (7th ed.): https://insights.sei.cmu.edu/library/common-sense-guide-to-mitigating-insider-threats-seventh-edition/
