---
name: ir-plan
description: Create or review an incident response plan aligned to NIST SP 800-61r3 and CSF 2.0 — roles, severity matrix, communication paths, decision authority, playbook coverage and testing cadence. Use when writing an IR plan, preparing for an audit or tabletop, or checking whether an existing plan would work in a real incident.
license: MIT
metadata:
  category: incident-response
  version: "2.0.0"
  verification: documented
---

# Incident Response Plan

NIST SP 800-61r3 (April 2025) frames incident response inside CSF 2.0's functions (Govern, Identify, Protect, Detect, Respond, Recover) rather than a standalone lifecycle. A plan must answer: *who decides what, how fast, with which information, and how do we reach them when email is down?*

## Required plan components

| Component | Must answer |
|---|---|
| Scope & definitions | What is an event vs. incident vs. breach; what systems/business units are covered |
| Roles | Incident commander, technical lead, scribe, comms, legal, privacy, executive sponsor — with deputies |
| Decision authority | Who can isolate a server, disable an executive's account, take a revenue system offline, engage outside counsel/IR retainer, pay/decline extortion (legal/board) |
| Severity matrix | Criteria (impact, data, scope, safety) → SLAs for response and notification |
| Communications | Primary and **out-of-band** channels (assume corporate email/IdP compromised); contact tree incl. after-hours |
| External parties | IR retainer, cyber insurer (notification clause!), counsel, regulators, law enforcement, key vendors |
| Regulatory clocks | GDPR 72h, SEC 8-K Item 1.05 (4 business days after materiality determination), NIS2 24h early warning, DORA, HIPAA, sector rules |
| Playbooks | Ransomware, BEC, credential compromise, cloud account takeover, data exfiltration, insider, DDoS, third-party breach |
| Evidence handling | Preservation, chain of custody, legal hold trigger |
| Recovery | Integration with BC/DR, restore priorities, criteria to return to production |
| Testing | Tabletop ≥ annually (technical + executive), playbook drills, plan review after each major incident |

## Review workflow

1. Gather the plan, playbooks, contact lists, retainer/insurance contracts.
2. Walk a realistic scenario (e.g., ransomware at 02:00 Saturday with IdP compromise) through the plan; note every point where the reader cannot answer "who/what/how".
3. Verify contact data is current (call a sample) and that out-of-band channels exist and are provisioned.
4. Check playbook coverage against the organization's top risks and recent incidents.
5. Check regulatory obligations with legal for each jurisdiction/sector.
6. Produce findings ranked by impact on response speed.

## Output template

```
IR plan review — <org> <date>
Scenario walked: <>
Gaps (ranked):
 1. <gap> — impact: <> — fix: <> — owner: <>
Coverage: playbooks present/missing: <>
Regulatory clocks confirmed with legal: yes/no
Next test: <date/type>
```

## Related skills

`incident-command`, `ransomware-response`, `recovery-exercise`, `privacy-incident-assessment`, `after-action`

## References

- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST CSF 2.0: https://www.nist.gov/cyberframework
- SEC cybersecurity disclosure rule (Form 8-K Item 1.05): https://www.sec.gov/rules-regulations/2023/07/s7-09-22
- CISA tabletop exercise packages: https://www.cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages
