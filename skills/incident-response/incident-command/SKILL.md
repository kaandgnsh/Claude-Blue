---
name: incident-command
description: Run or support incident command for an active security incident — establish roles, battle rhythm, decision log, objectives and status reporting. Use when an incident has been declared, a war room is forming, or an incident is drifting without clear ownership.
license: MIT
metadata:
  category: incident-response
  version: "2.0.0"
  verification: documented
---

# Incident Command

The incident commander (IC) coordinates; they do not do hands-on analysis. Clear objectives and a cadence beat heroics.

## First 60 minutes

1. **Name the IC and a scribe.** Announce in the incident channel. Everyone else is "operations".
2. **Open an out-of-band channel** if identity, email or chat may be compromised (pre-provisioned Signal/phone bridge/separate tenant). Assume the attacker can read the primary channel until proven otherwise.
3. **Set initial objectives** (example): (1) determine scope of access, (2) preserve evidence, (3) stop further harm to <crown jewel>, (4) keep leadership informed.
4. **Assign workstreams** with leads: Investigation, Containment, Comms/Stakeholders, Legal/Privacy, Business continuity.
5. **Start the decision log** (time, decision, decision-maker, rationale, evidence).
6. **Set the battle rhythm**: ops sync every 1–2h during active response; leadership brief every 4–8h; written status after each.

## Running the incident

- Each sync: current facts (not theories), objectives status, blockers, decisions needed, next sync time.
- Keep a **single source of truth** document: timeline, entity list, actions, open questions.
- Track every action as a ticket with owner and state; containment actions record verification.
- Shield responders: route executive questions through IC/comms.
- Enforce operational security: no IOC searches on public sandboxes for targeted samples without approval; no tipping the attacker (e.g. mass password resets before scoping).
- Plan for fatigue: shift rotation after 12h; handoff via `shift-handoff`.

## Status report template

```
INCIDENT <id> — status #<n> — <UTC time>   Severity: <>   IC: <>
Situation: <2–3 sentences>
Objectives: 1 <status>  2 <status>  3 <status>
Key facts since last update: <>
Decisions made: <>   Decisions needed (by whom/when): <>
Business impact: <>   Next update: <time>
```

## Decision log entry

`<UTC> | <decision> | <decided by> | <options considered> | <evidence/rationale> | <reversible? y/n>`

## Exit criteria

Containment verified, eradication plan approved, monitoring for re-entry in place, recovery owner named, notifications decided by legal, after-action scheduled.

## Related skills

`incident-scoping`, `containment-plan`, `escalation-decision`, `shift-handoff`, `after-action`

## References

- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- FEMA ICS principles (adapted widely to cyber IR): https://training.fema.gov/emiweb/is/icsresource/
