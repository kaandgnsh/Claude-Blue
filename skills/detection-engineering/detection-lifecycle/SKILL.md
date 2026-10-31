---
name: detection-lifecycle
description: Govern the detection lifecycle — intake and prioritization, development, testing, deployment, monitoring of efficacy (precision, volume, MTTD), periodic review, tuning and retirement. Use when running a detection engineering program, reviewing stale or noisy rules, or defining detection quality standards.
license: MIT
metadata:
  category: detection-engineering
  version: "2.0.0"
  verification: documented
---

# Detection Lifecycle

## Stages

1. **Intake**: requests from intel, incidents, hunts, red team, compliance. Each request states the threat, data required, and desired response.
2. **Prioritize**: threat relevance × impact × feasibility (telemetry exists?) × current coverage gap.
3. **Develop**: Sigma/native rule, ADS doc, runbook (`alerting-detection-strategy`, `runbook-authoring`).
4. **Test**: unit + emulation (`detection-testing`).
5. **Deploy**: via `detection-as-code`, start as `experimental` (low severity / shadow mode) for 1–2 weeks.
6. **Monitor**: per-rule metrics.
7. **Review**: quarterly for noisy/critical rules, annually for all.
8. **Retire**: when telemetry no longer exists, technique irrelevant, or superseded — record why.

## Per-rule metrics

| Metric | Target/use |
|---|---|
| Alert volume per day | SOC capacity planning |
| Precision (TP+BTP)/(all closed) | Flag rules < 10–20% for tuning |
| Silence (no alerts in 90 days) | Verify still functional (test) rather than assuming quiet = fine |
| Mean time to triage | Runbook clarity |
| Last validation date | Coverage claims |
| Exclusion count & age | Blind-spot risk |

Splunk example for precision (if dispositions are recorded on notables):
```spl
`notable` | search earliest=-90d | stats count(eval(disposition="true_positive")) as tp count as total by rule_name | eval precision=round(tp/total,2) | sort precision
```
(Field names depend on Splunk ES version and your disposition model.)

## Review checklist

- [ ] Still maps to a relevant threat.
- [ ] Data source healthy; fields unchanged after vendor/schema updates.
- [ ] Tested within interval.
- [ ] Exclusions still justified and unexpired.
- [ ] Runbook current.

## Related skills

`detection-as-code`, `alert-tuning`, `detection-testing`, `soc-performance-metrics`

## References

- Palantir ADS framework: https://github.com/palantir/alerting-detection-strategy-framework
- Detection Engineering Maturity Matrix (Kyle Bailey): https://detectionengineering.io/
