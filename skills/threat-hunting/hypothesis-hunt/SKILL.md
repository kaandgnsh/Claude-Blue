---
name: hypothesis-hunt
description: Plan and execute a hypothesis-driven threat hunt (PEAK / TaHiTI style) — form a testable hypothesis from intel or ATT&CK, confirm data readiness, query, analyze, and document results including negative findings and new detections. Use when starting a proactive hunt, turning a threat report into hunting activity, or structuring a hunting program.
license: MIT
metadata:
  category: threat-hunting
  version: "2.0.0"
  verification: documented
---

# Hypothesis-Driven Hunt

## Hunt types (PEAK framework)

- **Hypothesis-driven**: "Adversary X uses scheduled tasks named like updaters to persist on file servers."
- **Baseline / anomaly** (`stack-counting-hunt`): find the rare in the common.
- **Model-assisted (M-ATH)**: ML/statistics to surface outliers (e.g. `beaconing-hunt`).

## Workflow

1. **Prepare**
   - Trigger: threat report, new ATT&CK technique, incident lesson, red-team finding, crown-jewel risk.
   - Hypothesis: *who* (actor/TTP), *what* (observable behaviour), *where* (asset population), *when* (time window). Must be falsifiable.
   - Data: list required sources and fields; run `hunt-data-readiness` checks.
   - Scope and time-box (e.g., 2–5 days).
2. **Execute**
   - Start broad, then filter known-good with documented reasons.
   - Pivot on anything anomalous; keep a running query log.
   - Escalate immediately if you find an active intrusion (`escalation-decision`) — the hunt becomes an incident.
3. **Act**
   - Document findings: confirmed malicious, suspicious-unresolved, benign-explained, data gaps.
   - Convert durable logic to detections (`hunt-to-detection`).
   - File telemetry gaps and hardening recommendations.

## Hypothesis template

```
ID: H-<yyyy>-<nn>   Owner: <>   Time-box: <dates>
Hypothesis: <actor/TTP> is <behaviour> on <assets> during <window>.
ATT&CK: <technique IDs>
Rationale/intel: <source>
Data required: <source.table fields> — readiness: <ok/gap>
Success criteria: evidence that confirms or refutes, including what "absent" looks like.
```

## Hunt report

```
Result: confirmed | refuted | inconclusive (data gap)
Queries: <verbatim with time ranges and result counts>
Findings: <entity, evidence, verdict>
Benign explanations recorded: <>
Detections created: <ids>   Gaps filed: <tickets>
Time spent: <h>
```

## Related skills

`hunt-data-readiness`, `stack-counting-hunt`, `beaconing-hunt`, `hunt-to-detection`, `intel-to-detection`

## References

- PEAK Threat Hunting Framework (Splunk SURGe): https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html
- TaHiTI methodology: https://www.betaalvereniging.nl/en/safety/tahiti/
- MITRE ATT&CK: https://attack.mitre.org/
