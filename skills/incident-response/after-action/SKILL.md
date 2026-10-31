---
name: after-action
description: Run a blameless post-incident review that produces a factual timeline, root and contributing causes, what worked, and tracked corrective actions with owners. Use after a significant incident, near miss or exercise, or when lessons-learned items keep not getting done.
license: MIT
metadata:
  category: incident-response
  version: "2.0.0"
  verification: documented
---

# After-Action Review

## Workflow

1. **Schedule within 2 weeks** of closure while memory is fresh; include responders, system owners, and decision-makers.
2. **Build the factual timeline first** (from the case record) and circulate it before the meeting for corrections.
3. **Walk the timeline**, asking at each phase: what did we know, what did we do, what would have let us act sooner or better?
4. **Measure**: time to detect (first malicious event → first alert), time to triage, time to contain, time to recover; detection source (internal alert, third party, user report).
5. **Identify causes** with "5 whys" or a contributing-factor list across: prevention control, detection gap, process, people/training, tooling, third party. Avoid naming individuals as root cause.
6. **Corrective actions**: specific, owned, dated, prioritized; each tied to a cause. Track in the risk/ticket system and report closure.

## Questions that surface real gaps

- Which attacker step had *no* detection? Which had a detection that was ignored or closed?
- Where did we lose time waiting (approvals, access, contacts, vendor)?
- Did the out-of-band channel and contact list work?
- What telemetry did we wish we had? Was retention long enough?
- Would this have been prevented by a control we believed was in place?

## Output template

```
After-action — <incident id> — <date>
Summary: <>
Metrics: TTD <> | TTT <> | TTC <> | TTR <> | detection source <>
Timeline: <link>
What worked: <>
Contributing factors: <factor> → <evidence>
Corrective actions:
 # | action | cause addressed | owner | due | priority | ticket
Detection gaps → new detections: <>
```

## Related skills

`incident-report-writing`, `detection-lifecycle`, `attack-coverage-mapping`, `risk-register`

## References

- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- Google SRE, Postmortem culture: https://sre.google/sre-book/postmortem-culture/
