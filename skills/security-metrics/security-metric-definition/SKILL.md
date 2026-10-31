---
name: security-metric-definition
description: Define security metrics that drive decisions — goal-question-metric method, precise formulas, data sources, owners, targets and thresholds, leading vs. lagging indicators, and anti-gaming checks — and present them to leadership. Use when creating a security dashboard, KPI/KRI set, board report, or when existing metrics are vanity counts.
license: MIT
metadata:
  category: security-metrics
  version: "2.0.0"
  verification: documented
---

# Security Metric Definition

## Goal → Question → Metric

| Goal | Question | Metric |
|---|---|---|
| Reduce account takeover | Are privileged identities protected by phishing-resistant MFA? | % privileged accounts with phishing-resistant MFA enforced (from IdP policy + sign-in evidence) |
| Shrink exploit window | How fast do we fix exploited vulnerabilities on exposed assets? | Median days from KEV listing to remediation, internet-facing assets |
| Detect intrusions early | How long do attackers operate before detection? | Median dwell time (first malicious event → detection) from incidents/purple tests |
| Recover from ransomware | Can we restore critical services in time? | % Tier 1 services with successful restore test within RTO in last 6 months |

## Metric specification

```
Name: <>   ID: <>   Owner: <>
Definition / formula: numerator / denominator, inclusion & exclusion rules
Data source & query: <system, query text or report>
Frequency: <weekly/monthly>   Target: <>   Thresholds: green/amber/red
Type: leading | lagging   KRI? yes/no (linked risk ID)
Known limitations: <coverage gaps, data quality>
Action when red: <who does what>
```

## Quality rules

- Denominators from an authoritative inventory (coverage of what?).
- Prefer distributions (median, p90) over averages for time metrics.
- Pair metrics to avoid gaming: "alerts closed per analyst" with "QA reopen rate"; "patch SLA met" with "exceptions granted".
- Each metric must have an owner and a decision it informs; delete metrics nobody acts on.
- Report trend + context, not single numbers.

## Board/executive view

5–8 metrics tied to top risks, trend over 4 quarters, one-line interpretation each, decisions requested.

## Related skills

`soc-performance-metrics`, `detection-coverage-metrics`, `risk-register`, `risk-quantification-fair`

## References

- NIST SP 800-55 Vol. 1 Measurement Guide for Information Security (2024): https://csrc.nist.gov/pubs/sp/800/55/v1/final
- CIS Controls v8.1 measures and metrics: https://www.cisecurity.org/controls
