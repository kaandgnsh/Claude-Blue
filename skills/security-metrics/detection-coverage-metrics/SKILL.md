---
name: detection-coverage-metrics
description: Measure detection and telemetry coverage honestly — log source coverage vs. asset inventory, EDR coverage, ATT&CK technique coverage split into telemetry/detection/validated, detection test pass rates and time since last validation. Use when reporting detection capability, prioritizing detection engineering work, or challenging an over-optimistic coverage heatmap.
license: MIT
metadata:
  category: security-metrics
  version: "2.0.0"
  verification: documented
---

# Detection Coverage Metrics

## Metric set

| Metric | Formula |
|---|---|
| Telemetry coverage | Assets sending required source / assets in scope (per source: EDR, Windows Security, Linux audit, cloud trail, IdP) |
| Field completeness | Events with required fields populated / events (e.g., 4688 with command line) |
| Technique detection coverage | Prioritized techniques with ≥ 1 production detection / prioritized techniques |
| **Validated** coverage | Prioritized techniques with a detection that passed a test in the last 12 months / prioritized techniques |
| Validation freshness | Median days since last successful test per detection |
| Test pass rate | Passed detection tests / tests run (purple team, emulation, unit) |
| Mean detection latency | Event time → alert time in tests |

Always state the **denominator**: "prioritized techniques" = techniques from the threat profile (`intelligence-requirements`), not all ~700 ATT&CK techniques.

## Data sources

Detection repository metadata (ATT&CK tags, test IDs), test results log (`detection-testing`), asset inventory vs. SIEM host counts (`hunt-data-readiness`), EDR coverage (`edr-coverage-health`).

## Presenting

Show three layers side by side per tactic: telemetry / detection / validated. A tactic with 90% "detection" but 20% "validated" is the true story. Track quarterly trend.

## Example report row

| Tactic | Prioritized techniques | Telemetry ≥ 90% assets | Production detection | Validated ≤ 12 months |
|---|---|---|---|---|
| Credential Access | 9 | 8 | 7 | 4 |
| Lateral Movement | 7 | 5 | 5 | 2 |

Interpretation line: "Lateral movement: 5 of 7 techniques have detections, only 2 validated; Linux SSH lateral movement lacks telemetry (auditd rollout 40%)."

## Related skills

`attack-coverage-mapping`, `detection-testing`, `edr-coverage-health`, `security-metric-definition`

## References

- MITRE ATT&CK Navigator: https://github.com/mitre-attack/attack-navigator
- MITRE CTID Measure, Prioritize, Defend / Threat-informed defense: https://ctid.mitre.org/
