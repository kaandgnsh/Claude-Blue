---
name: shift-handoff
description: Produce a SOC shift handoff that transfers open incidents, pending actions, platform health issues and watch items without losing context. Use at shift change, when handing a case to another team or time zone, or when summarizing the queue for a lead.
license: MIT
metadata:
  category: soc-operations
  version: "2.0.0"
  verification: documented
---

# Shift Handoff

Most dropped incidents are dropped at handoff. A handoff lists what the next shift must *do*, not what this shift *did*.

## Workflow

1. Pull the open queue sorted by severity then age. For each case note owner, status, and the single next action with a deadline.
2. List **time-bound items**: pending approvals, containment awaiting confirmation, vendor/legal callbacks, IOC sweeps running, embargoed advisories.
3. List **platform health**: log sources silent beyond their expected interval, EDR sensors offline on critical assets, failed SOAR playbooks, ingestion lag. Example check (Sentinel): `Heartbeat | summarize last=max(TimeGenerated) by Computer | where last < ago(1h)`; Splunk: `| tstats latest(_time) as last where index=* by index, sourcetype | where last < relative_time(now(), "-2h")`.
4. List **watch items**: entities under heightened monitoring, temporary detections deployed, threat intel requiring attention.
5. Do a **verbal or live walkthrough** of anything critical; the written note is the record, not a substitute for a conversation on a P1.
6. Incoming analyst acknowledges in writing; ownership changes in the ticketing system, not just in chat.

## Template

```
Shift handoff <date> <from shift> → <to shift>   Lead: <>
CRITICAL / ACTIVE
 - <case> sev<> owner→<new owner>  Next: <action> by <UTC time>  Blocker: <>
PENDING APPROVALS / CALLBACKS
 - <item> waiting on <who> since <t>
PLATFORM HEALTH
 - <source> silent since <t> (ticket <>)
WATCH ITEMS
 - <entity> monitor for <behaviour> until <date>; temp rule <id> expires <date>
QUEUE: <n> open (<by severity>), oldest <age>
Acknowledged by: <name> at <t>
```

## Pitfalls

- "Monitoring" without a defined trigger and end date.
- Leaving containment state ambiguous ("isolated?"). State verified state and how it was verified.
- Handoffs only in chat; they are not searchable or auditable later.

## Related skills

`incident-command`, `case-documentation`, `log-pipeline-health`, `soc-performance-metrics`

## References

- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
