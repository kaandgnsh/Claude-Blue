---
name: attack-coverage-mapping
description: Map detections and telemetry to MITRE ATT&CK, build ATT&CK Navigator layers, distinguish tested vs. claimed coverage, and prioritize gaps by threat relevance (threat-informed defense). Use when reporting detection coverage, planning a detection roadmap, or assessing readiness against a specific threat actor.
license: MIT
metadata:
  category: detection-engineering
  version: "2.0.0"
  verification: documented
---

# ATT&CK Coverage Mapping

## Avoid the "green heatmap" trap

A rule tagged with a technique does not mean the technique is covered. Score each technique on separate dimensions:

| Dimension | Values |
|---|---|
| Telemetry | none / partial (some assets or fields) / full |
| Detection | none / hunt-only / alert |
| Validation | untested / tested (date, method) |
| Procedure breadth | how many known procedures/variations the logic catches |

## Workflow

1. **Export detections** with technique tags from the detection repo or SIEM.
2. **Map telemetry** per data component (ATT&CK data sources) with coverage % across asset classes.
3. **Select relevant techniques**: from threat intel on actors targeting your sector (`intelligence-requirements`), recent incidents, and frequency data (e.g., Red Canary Threat Detection Report top techniques).
4. **Score** each relevant technique on the dimensions above.
5. **Build Navigator layers** (JSON, `techniques[].score`, `comment`, `color`) for: telemetry, detection, validated detection, threat priority. Overlay to show gaps where priority is high and validated coverage is low.
6. **Plan**: backlog of detections/telemetry projects ranked by priority × gap; feed `detection-lifecycle`.

## Navigator layer snippet

```json
{
  "name": "Validated detections 2026-Q4",
  "domain": "enterprise-attack",
  "versions": {"layer": "4.5", "navigator": "5.1.0"},
  "techniques": [
    {"techniqueID": "T1003.001", "score": 3, "comment": "2 rules, tested 2026-10-12 (atomic #1, #2)"},
    {"techniqueID": "T1558.003", "score": 1, "comment": "Rule deployed, untested"}
  ],
  "gradient": {"colors": ["#ffffff", "#66b1ff"], "minValue": 0, "maxValue": 3}
}
```
Check the layer format version supported by your Navigator instance.

## Report

`Technique | Priority (why) | Telemetry | Detection | Last validated | Gap action | Owner`

## Related skills

`detection-testing`, `detection-coverage-metrics`, `intelligence-requirements`, `hunt-data-readiness`

## References

- MITRE ATT&CK Navigator: https://github.com/mitre-attack/attack-navigator
- MITRE CTID Threat-Informed Defense resources: https://ctid.mitre.org/
- Red Canary Threat Detection Report: https://redcanary.com/threat-detection-report/
