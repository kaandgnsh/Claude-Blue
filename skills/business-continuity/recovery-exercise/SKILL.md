---
name: recovery-exercise
description: Design and run cyber recovery and incident exercises — tabletop (executive and technical), functional restore drills, full failover tests — with realistic injects, objectives, measured outcomes (RTO/RPO, decision times) and tracked improvement actions. Use when planning annual exercises, testing ransomware or cloud outage readiness, or validating a new IR/BC plan.
license: MIT
metadata:
  category: business-continuity
  version: "2.0.0"
  verification: documented
---

# Recovery and Incident Exercises

## Exercise types

| Type | Purpose | Participants |
|---|---|---|
| Executive tabletop | Decisions: downtime tolerance, extortion, disclosure, communications | Executives, legal, comms, CISO |
| Technical tabletop | Walk through detection → containment → recovery steps | SOC, IR, IT ops, app owners |
| Functional drill | Actually restore systems (AD forest recovery, database restore, failover) | IT ops, backup team |
| Full-scale / red-team-integrated | End-to-end under realistic conditions | Broad |

## Design

1. **Objectives** (measurable): "Restore Tier 1 order service from immutable backup within 24h RTO"; "Decide on external disclosure within 4h of materiality inputs".
2. **Scenario** grounded in threat profile (ransomware with AD compromise, SaaS provider outage, cloud account takeover, insider data theft).
3. **Injects** timed: initial alert, ransom note, data-leak-site post, media inquiry, regulator question, backup turns out corrupted, key person unavailable, email/chat unavailable (forces out-of-band comms).
4. **Ground rules**: no-fault, what's in/out of scope, how to handle real incidents during the exercise.
5. **Observers/scribes** capture decisions and times.

## Measure

Time to detect/escalate/declare, time to key decisions, restore times vs. RTO, data loss vs. RPO, communication effectiveness, gaps in runbooks/contacts/access.

## After

Hot wash immediately; written after-action report within 2 weeks (`after-action`) with owned corrective actions; re-test failed objectives.

## Related skills

`ir-plan`, `after-action`, `backup-assurance`, `ransomware-recovery`

## References

- CISA Tabletop Exercise Packages (CTEP): https://www.cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages
- FEMA HSEEP (exercise program methodology): https://www.fema.gov/emergency-managers/national-preparedness/exercises/hseep
- NIST SP 800-84 Guide to Test, Training, and Exercise Programs: https://csrc.nist.gov/pubs/sp/800/84/final
