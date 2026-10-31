---
name: soc-performance-metrics
description: Measure SOC performance and health — alert volume and precision per rule, MTTA/MTTT/MTTC, queue age and SLA breaches, escalation accuracy, case QA scores, analyst load and automation impact — with correct definitions and SIEM/ticketing queries. Use when reporting SOC effectiveness, diagnosing backlog or burnout, or setting SOC SLAs.
license: MIT
metadata:
  category: security-metrics
  version: "2.0.0"
  verification: documented
---

# SOC Performance Metrics

## Core metrics

| Metric | Definition | Watch for |
|---|---|---|
| MTTA (acknowledge) | Alert created → analyst assigned | Queue staffing gaps by hour |
| MTTT (triage) | Alert created → verdict | Runbook clarity, enrichment gaps |
| MTTC (contain) | Incident declared → containment verified | Approval delays, tool access |
| Precision per rule | (TP + BTP) / closed alerts | Rules < 10–20% → `alert-tuning` |
| Queue age | Open alerts by age bucket; SLA breaches by severity | Silent backlog |
| Escalation accuracy | Escalations confirmed as incidents / escalations | Over- or under-escalation |
| Reopen / QA rate | Cases failing QA review (`case-documentation`) | Quality vs. speed trade-off |
| Analyst load | Alerts per analyst-hour, after-hours pages | Burnout risk |
| Detection source | % incidents detected internally vs. reported by third parties | Detection maturity |

Use **medians and p90**, segmented by severity and source; exclude auto-closed duplicates explicitly.

## Example queries

Sentinel incidents:
```kusto
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend ttt_min = datetime_diff('minute', ClosedTime, CreatedTime)
| summarize p50=percentile(ttt_min, 50), p90=percentile(ttt_min, 90), n=count() by Severity, Classification
```
Splunk ES notables (field names vary by version):
```spl
`notable` earliest=-30d | eval ttt=(review_time-_time)/60 | stats median(ttt) as p50 perc90(ttt) as p90 count by urgency, rule_name
```

## Interpretation

Faster isn't always better — falling MTTT with rising QA failures signals rubber-stamping. Pair speed with quality; track trends monthly; tie improvements to actions (tuning, automation, staffing).

## Related skills

`security-metric-definition`, `alert-tuning`, `detection-lifecycle`, `shift-handoff`

## References

- SANS SOC Survey (annual): https://www.sans.org/white-papers/
- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
