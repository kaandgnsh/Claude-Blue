---
name: hunt-data-readiness
description: Verify that the telemetry needed for a hunt or detection actually exists, is complete and parsed correctly — source coverage by asset population, field population rates, retention, latency, clock skew and audit-policy settings. Use when preparing a hunt, before trusting a "no results" outcome, or when a detection silently never fires.
license: MIT
metadata:
  category: threat-hunting
  version: "2.0.0"
  verification: documented
---

# Hunt Data Readiness

"No results" is only meaningful if the data could have contained the answer.

## Checks

| Dimension | Question | Example query |
|---|---|---|
| Coverage | Which hosts/users/accounts send this source? Compare to inventory. | Splunk: `\| tstats dc(host) where index=wineventlog sourcetype=*Security* by index` |
| Field population | Is the needed field present and non-empty? | Sentinel: `SecurityEvent \| where EventID==4688 \| summarize pct=100.0*countif(isnotempty(CommandLine))/count()` |
| Audit policy | Is the event generated at all? | `auditpol /get /subcategory:"Process Creation"`; Sysmon config includes event type |
| Retention | Does retention cover the hunt window? | Index/table retention settings; hot vs. archive tiers |
| Latency | Ingestion delay | Sentinel: `T \| extend lag = ingestion_time() - TimeGenerated \| summarize percentiles(lag, 50, 95)` |
| Parsing | Are values in the right fields / normalized? | Sample raw vs. parsed events |
| Clock | Source time vs. ingest time skew | Compare `_time` vs `_indextime` (Splunk) |
| Continuity | Gaps/outages in the window | `\| tstats count where index=X by _time span=1h` and look for zeros |

## Common failure modes

- **Audit policy off**: 4688 without command line, no 4769 on some DCs, Kerberos auditing missing on new DCs built after the GPO was scoped.
- **Partial agent rollout**: Sysmon/EDR on workstations but not servers; Linux hosts absent.
- **Sampling/filters upstream**: pipeline drops "noisy" event IDs (e.g. 4662, 5145) that the hunt needs; Cribl/Logstash routes send them to cheaper storage that isn't searched.
- **Schema drift**: vendor update renames a field; the parser leaves it in raw text so field-based queries return nothing.
- **Time misparsing**: local-time sources ingested as UTC shift events by hours, falling outside the hunt window.

Record each failure as a ticket for the owning team and state its effect on the hunt conclusion ("refuted for workstations; inconclusive for servers").

## Output

```
Hunt <id> data readiness — <date>
Source | Needed fields | Coverage (n/N, %) | Field fill % | Retention | Latency p95 | Gaps | Status
Decision: proceed | proceed with documented gaps | blocked (ticket)
```

## Related skills

`hypothesis-hunt`, `log-source-onboarding`, `log-pipeline-health`, `detection-coverage-metrics`

## References

- MITRE ATT&CK data sources/components: https://attack.mitre.org/datasources/
- OSSEM Detection Model: https://github.com/OTRF/OSSEM
