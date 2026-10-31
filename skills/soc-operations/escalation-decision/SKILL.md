---
name: escalation-decision
description: Decide whether and to whom a security event should be escalated (Tier 2, incident response, legal, privacy, executives, law enforcement) using explicit criteria and a structured escalation message. Use when an analyst is unsure whether something is an incident, needs to declare an incident, or must notify stakeholders.
license: MIT
metadata:
  category: soc-operations
  version: "2.0.0"
  verification: documented
---

# Escalation Decision

Escalate on criteria, not on anxiety or on politeness. Under-escalation costs dwell time; over-escalation burns responder trust.

## Escalate to incident response (declare an incident) when any is true

- Confirmed malicious code execution or hands-on-keyboard activity on any asset.
- Confirmed unauthorized access to a privileged account, IdP admin, cloud root/global admin, CI/CD, or backup system.
- Evidence of credential theft (LSASS access, token theft, AiTM phishing success) even without further use yet.
- Data access or exfiltration indicators involving regulated or confidential data.
- Ransomware precursors (mass file rename, shadow copy deletion, backup tampering, AV disablement at scale).
- Same TTP on ≥2 unrelated hosts/users (campaign).
- A third party (vendor, CERT, law enforcement, researcher) reports compromise.

## Parallel notifications (decided by IR lead, not tier-1)

| Trigger | Notify |
|---|---|
| Personal data potentially affected | Privacy/DPO — GDPR 72-hour clock may start at awareness |
| Possible litigation, insider, or employee involvement | Legal, HR (via legal) |
| Material business impact / public exposure | Executive/crisis team, communications |
| Critical infrastructure / sector rules (e.g. SEC 8-K, NIS2, DORA) | Compliance/legal to evaluate reporting duties |
| Extortion, wire fraud | Legal → law enforcement (e.g. FBI IC3) |

## Workflow

1. Map evidence to the criteria above; cite the specific item.
2. Assign provisional severity using the organization's matrix (impact × scope × confidence).
3. Send a structured escalation (template below) through the official channel and page on-call for high/critical.
4. Keep working read-only evidence collection until the receiver acknowledges; record the acknowledgment time.
5. If the escalation is declined, record who declined and why.

## Escalation message

```
ESCALATION sev<> — <one-line what>
Detected: <UTC> via <source/rule>   Case: <id>
Confirmed facts: <bullets with evidence>
Affected: <hosts/users/data>  Business owner: <>
Criteria met: <which>
Actions taken: <read-only collection / none>   Containment proposed: <>
Need from you: <decision/approval> by <time>
Analyst: <name/contact>
```

## Safety

Do not alert a suspected insider or notify external parties yourself; regulatory and law-enforcement notifications are made by legal/IR leadership.

## Related skills

`alert-triage`, `incident-command`, `incident-scoping`, `privacy-incident-assessment`, `insider-threat-investigation`

## References

- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- CISA Federal Incident Notification Guidelines: https://www.cisa.gov/federal-incident-notification-guidelines
- GDPR Art. 33: https://gdpr-info.eu/art-33-gdpr/
