---
name: bas-results-review
description: Interpret breach and attack simulation (BAS) results critically, separating prevented, detected and logged-only outcomes, checking that the simulated procedures resemble real threats, validating results against SIEM and EDR evidence, and turning findings into prioritized fixes rather than a score. Use when reviewing a BAS report or dashboard (for example AttackIQ, SafeBreach, Cymulate, Picus), selecting BAS scenarios, or when leadership asks what a BAS score means.
license: MIT
metadata:
  category: security-testing
  version: "2.2.0"
  verification: documented
---

# BAS Results Review

BAS platforms produce a percentage. The percentage depends on which scenarios were run, how "detected" is defined, and whether anyone checked the SOC actually received anything. Review the method before the number.

## 1. Check what was simulated

| Question | Why it matters |
|---|---|
| Which scenarios ran, and on which agents/hosts? | A 95% score on 3 workstations says nothing about servers or cloud |
| Do the procedures match threats relevant to you (CTI-driven), or vendor defaults? | Generic tool signatures inflate prevention rates |
| Were payloads real techniques or file drops of known samples? | Hash-based blocking of known samples is the easiest win; behaviours matter more |
| Network scenarios: real egress path or simulated between two agents on the same subnet? | Same-subnet tests bypass the proxy and firewall you care about |
| Cloud scenarios: run against real tenants with production policies? | Sandboxed accounts lack org policies and logging |

## 2. Normalize outcomes

Map vendor outcome labels to four states and recount:

| State | Meaning |
|---|---|
| `prevented` | The action failed because a control stopped it (evidence: block event) |
| `detected` | The action succeeded and an alert reached the SOC queue |
| `logged-only` | Telemetry exists in the SIEM/EDR but no alert fired |
| `not-observed` | No telemetry found |

Many BAS dashboards count "detected" when the EDR produced any event, or when an integration query found a log line. That is `logged-only` from the SOC's point of view.

## 3. Verify against your own evidence

Pick a sample (at least 10 results, including every "detected" for high-priority techniques) and confirm in the SIEM/EDR:

```kusto
// Sentinel: alerts on BAS agents in the run window (compare with the BAS "detected" list)
SecurityAlert
| where TimeGenerated between (datetime(2026-10-30T08:00:00Z) .. datetime(2026-10-30T20:00:00Z))
| where Entities has_any ("bas-agent-01", "bas-agent-02")
| summarize alerts = make_set(AlertName), first = min(TimeGenerated) by CompromisedEntity
```

Export the BAS execution log and score it with the matcher in `detection-validation` to get per-procedure status and latency from your alerts, not from the BAS vendor's integration.

## 4. Prioritize findings

Rank gaps by: threat relevance (technique used by actors targeting your sector) × asset criticality of affected scope × ease of exploitation (does the gap need prior admin access?). A missed prevention on a technique that requires domain admin first is lower priority than an allowed-silent initial access technique.

| Priority | Example |
|---|---|
| P1 | Initial access or credential theft `not-observed` on standard workstations |
| P2 | Lateral movement `logged-only` (telemetry exists; write the detection) |
| P3 | Post-exploitation discovery techniques `logged-only` with low signal value |

## 5. Report to leadership without a misleading score

```markdown
# BAS review: <period>   Scope: <agents/environments>   Scenarios: <count, source>
Outcome (normalized): prevented 41% | detected 22% | logged-only 27% | not observed 10%
Verified sample: 15 results; 3 vendor-"detected" results had no SOC alert (re-labelled logged-only)
Top gaps: <3-5 items, priority, owner, due>
Trend vs. last quarter on the same scenario set: <delta>
```

Only compare scores over time when the scenario set and agent scope are identical.

## Related skills

`detection-validation`, `control-validation`, `attack-coverage-mapping`, `purple-team-exercise`, `detection-coverage-metrics`, `security-test-planning`

## References

- MITRE ATT&CK: https://attack.mitre.org/
- MITRE Center for Threat-Informed Defense, Top ATT&CK Techniques: https://ctid.mitre.org/projects/top-attack-techniques/
- NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment): https://csrc.nist.gov/pubs/sp/800/115/final
