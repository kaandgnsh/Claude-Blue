---
name: privacy-preserving-ir
description: Run investigations and incident response with privacy safeguards — necessity and proportionality of data access, minimal evidence collection, restricted handling of employee and customer personal data, works-council/HR/legal involvement, reviewer access logging, and data minimization in reports and IOC sharing. Use when an investigation touches employee monitoring data, mailbox content, customer records, or cross-border data transfers.
license: MIT
metadata:
  category: privacy-engineering
  version: "2.0.0"
  verification: documented
---

# Privacy-Preserving Investigations

## Principles

1. **Purpose-bound**: document the investigation question; collect only data relevant to it.
2. **Proportionate**: start with metadata (who/when/where) before content (email bodies, file contents, chat messages); escalate to content with approval.
3. **Approved**: content review of employee communications requires legal/HR (and works-council where applicable) approval in many jurisdictions; record the approval.
4. **Restricted**: evidence stores with access limited to named investigators; access logged.
5. **Minimized outputs**: reports reference evidence IDs instead of pasting personal data; redact third parties not relevant to the case.
6. **Retention**: delete investigation copies when the case and any legal hold close.
7. **Transfers**: cross-border evidence transfers (e.g., EU → US) under appropriate safeguards; consider having local teams perform review.

## Practical controls

- Use metadata searches first: message trace, sign-in logs, file access logs (`m365-audit-investigation`).
- When content is necessary: targeted keyword/date-bounded eDiscovery searches instead of whole mailbox exports.
- Pseudonymize user names in broad hunts and dashboards; de-pseudonymize only for confirmed leads.
- Separate duties: analysts handling insider cases shouldn't investigate their own reporting chain.
- IOC sharing (`stix-taxii-misp`): strip victim identifiers, internal hostnames and usernames.

## Decision log entry

`<UTC> | data source/content accessed | purpose | approver | scope (users, dates, keywords) | outcome`

## Related skills

`insider-threat-investigation`, `telemetry-minimization`, `privacy-incident-assessment`, `case-documentation`

## References

- EDPB Guidelines on processing in the employment context / Article 29 WP Opinion 2/2017 on data processing at work: https://ec.europa.eu/newsroom/article29/items/610169
- ICO Employment practices — monitoring workers: https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/employment/monitoring-workers/
- NIST Privacy Framework: https://www.nist.gov/privacy-framework
