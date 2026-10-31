---
name: log-pipeline-health
description: Monitor and troubleshoot security log pipelines — silent sources, ingestion lag, dropped/filtered events, parsing failures, forwarder/agent health, queue backpressure, license throttling — across Splunk, Sentinel, Elastic and pipeline tools (Cribl, Vector, Fluent Bit, Logstash). Use when a source goes quiet, detections stop firing, or before trusting log completeness in an incident.
license: MIT
metadata:
  category: siem-engineering
  version: "2.0.0"
  verification: documented
---

# Log Pipeline Health

Attackers disable logging (ATT&CK T1685 Disable or Modify Tools and sub-techniques); pipelines also fail on their own. Either way detections go blind silently.

## Health signals

| Signal | Splunk | Sentinel | Elastic |
|---|---|---|---|
| Source silent | `| tstats latest(_time) as last where index=* by index, sourcetype, host | where last < relative_time(now(),"-4h")` | `union withsource=T * | summarize last=max(TimeGenerated) by T | where last < ago(4h)` (heavy — scope tables) or per-table queries; Heartbeat for agents | Fleet agent status; `max(@timestamp)` per data stream |
| Ingestion lag | `eval lag=_indextime-_time | stats perc95(lag) by sourcetype` | `extend lag=ingestion_time()-TimeGenerated | summarize percentile(lag,95) by Type` | ingest pipeline timestamps (`event.ingested - @timestamp`) |
| Volume anomaly | Compare daily count vs 7-day median per source | `summarize count() by bin(TimeGenerated,1h), Type` | Rollup/ML job on event rate |
| Parsing failures | `index=_internal log_level=WARN component=DateParserVerbose`; events with default `_time` | Rows with empty key columns; `_ResourceId` missing | `_ingest` pipeline failures, `error.message` |
| Forwarder/agent | Monitoring Console forwarder health, `index=_internal sourcetype=splunkd component=TcpOutputProc` | AMA `Heartbeat`, Data Collection Rule errors | Fleet agent unhealthy |
| Licence/throttle | License usage warnings | Daily cap reached (`Operation` table) | Ingest limits |

## Silence thresholds

Set per source from its natural rhythm: DC Security logs (minutes), firewall (minutes), CloudTrail (≈ 5–15 min delivery), M365 audit (can lag hours), batch API sources (poll interval × 2).

## Troubleshooting order

Source producing events? → collector receiving (agent logs)? → transport (TLS/syslog drops, queue full)? → pipeline transforms/filters dropping? → index/table routing → parsing/time extraction (events land at wrong `_time`) → search permissions.

## Output

`Source | Expected interval | Last event | Lag p95 | Volume vs baseline | Status | Ticket`

## Related skills

`log-source-onboarding`, `hunt-data-readiness`, `shift-handoff`, `edr-coverage-health`

## References

- Splunk Monitoring Console: https://docs.splunk.com/Documentation/Splunk/latest/DMC/DMCoverview
- Azure Monitor Agent troubleshooting: https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-troubleshoot-windows-vm
- MITRE ATT&CK T1685: https://attack.mitre.org/techniques/T1685/
