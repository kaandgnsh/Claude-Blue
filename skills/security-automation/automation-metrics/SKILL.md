---
name: automation-metrics
description: Measure whether security automation pays off and stays safe, covering run volume, success and failure rates, analyst time saved, decision precision of automatic closes and actions, time-to-containment deltas, and the maintenance cost of each playbook. Use when justifying or prioritizing SOAR work, deciding to retire or promote a playbook, or reporting automation value to SOC leadership.
license: MIT
metadata:
  category: security-automation
  version: "2.2.0"
  verification: documented
---

# Automation Metrics

Count outcomes, not runs. A playbook that runs 10,000 times a month and is ignored by analysts saves nothing; one that runs 30 times and contains ransomware in 2 minutes is worth the whole platform.

## Core metrics per playbook

| Metric | Definition | Source | Target / signal |
|---|---|---|---|
| Runs | Completed runs in period | SOAR run history | Trend only |
| Failure rate | Failed or timed-out runs ÷ runs | SOAR run history | < 2%; spikes mean connector/auth issues |
| Hand-off rate | Runs that ended in the analyst `on_error`/`default` path ÷ runs | Case comments / playbook output | Stable; a rise means inputs changed |
| Auto-close precision | Auto-closed cases later reopened or found true positive ÷ auto-closed | Case history (reopen, reclassification) | ≥ 99.5% correct |
| Action precision | Automatic actions labelled "wrong target" ÷ automatic actions | After-action labels | 0 wrong targets; any > 0 is reviewed |
| Time saved | (Manual handling minutes − residual minutes) × cases | Time study + case counts | Report in analyst-hours/month |
| Containment delta | Median detection→containment, automatic vs. manual path | Case timestamps | Show the gap explicitly |
| Maintenance cost | Engineer hours spent fixing/updating the playbook | Ticketing / sprint data | Retire if cost > saved time for 2 quarters |

## Measure manual effort once, properly

Time saved is the number leaders ask for and the one most often invented. Do a time study:

1. For one week, have analysts log minutes per step for 20+ cases of that alert type without automation (or from case timestamps before go-live).
2. After go-live, measure residual minutes for the same alert type.
3. Use medians, not means; one 4-hour case skews everything.

## Queries

```kusto
// Sentinel: incidents closed by an automation rule and later reopened (precision of automatic closure)
SecurityIncident
| where TimeGenerated > ago(90d)
| sort by TimeGenerated asc
| summarize statuses = make_list(Status), closers = make_set_if(ModifiedBy, Status == "Closed") by IncidentNumber
| where tostring(closers) has "Automation rule"
| extend reopened = tostring(statuses) matches regex @'"Closed".*"(New|Active)"'
| summarize autoClosed = count(), reopened = countif(reopened)
| extend precision = 1.0 - todouble(reopened) / autoClosed
```

`ModifiedBy` text depends on how the closure was made (automation rule, playbook identity, API client). Check a few auto-closed incidents first, or have the automation add a tag such as `auto-closed` and filter on `Labels` instead. In Splunk ES, the equivalent comes from the notable event review status history (`incident_review` lookup); filter by the reviewing user your automation runs as.

## Dashboard layout

1. **Value:** analyst-hours saved this month, containment delta, cases fully handled by automation.
2. **Safety:** wrong-target actions (must be 0), auto-close reopen count, circuit-breaker trips.
3. **Health:** failure rate and hand-off rate per playbook, connectors with rising 401/429 errors.
4. **Portfolio:** playbooks by runs vs. maintenance cost; candidates to retire or to promote from recommend-only.

## Decision rules

- **Promote** a playbook from recommend-only to acting when precision ≥ 99% over ≥ 50 cases and no open failure-path gaps (see `playbook-testing`).
- **Pause** automatic actions after any wrong-target action until root cause is fixed.
- **Retire** a playbook with no runs in 90 days, or maintenance cost above time saved for two quarters.

## Related skills

`soc-performance-metrics`, `automated-containment-guardrails`, `playbook-testing`, `security-metric-definition`, `soar-playbook-design`

## References

- Microsoft Sentinel SecurityIncident table: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityincident
- Microsoft Sentinel automation rules: https://learn.microsoft.com/en-us/azure/sentinel/automate-incident-handling-with-automation-rules
- SANS SOC Survey (automation and metrics sections): https://www.sans.org/white-papers/
