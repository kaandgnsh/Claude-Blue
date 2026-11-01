---
name: detection-validation
description: Score a whole adversary-emulation or purple-team run against the alerts the SIEM or EDR actually raised, classifying every executed test as detected, detected by an unexpected rule, or missed, with detection latency, using a bundled matcher. Use after an Atomic Red Team, Caldera or manual emulation campaign, after a BAS run, or when reporting which techniques the SOC would really see.
license: MIT
metadata:
  category: security-testing
  version: "2.2.0"
  verification: tested
---

# Detection Validation (campaign scoring)

`detection-testing` proves one rule works. This skill answers the campaign question: *we executed 40 procedures across 6 hosts, which ones did the SOC actually get alerted on, by which rule, and how fast?* Score from exported alerts, not from what the dashboard claims.

## 1. Record the execution log while testing

Every executed procedure gets a row the moment it runs. Use UTC and the hostname as the SIEM sees it.

```json
[
  {"id": "PT-01", "technique": "T1003.001", "host": "WS-12", "executed_at": "2026-10-30T10:00:00Z",
   "expect": ["LSASS Memory Access by Unsigned Process"], "window_min": 30},
  {"id": "PT-02", "technique": "T1059.001", "host": "WS-12", "executed_at": "2026-10-30T10:20:00Z",
   "expect": ["Encoded PowerShell Command"], "window_min": 30},
  {"id": "PT-03", "technique": "T1053.005", "host": "SRV-03", "executed_at": "2026-10-30T11:00:00Z",
   "expect": ["Scheduled Task Created Remotely"], "window_min": 60}
]
```

`expect` lists the rule names that *should* fire (from `attack-coverage-mapping`). Keep the procedure detail (command line, tool, variant) in the exercise notes; the scorer only needs time, host and expectation.

## 2. Export alerts for the exercise window

Export **raw alerts**, not incidents (incident grouping hides which rule fired).

```kusto
// Sentinel
SecurityAlert
| where TimeGenerated between (datetime(2026-10-30T09:45:00Z) .. datetime(2026-10-30T13:00:00Z))
| mv-expand e = todynamic(Entities)
| where tostring(e.Type) == "host"
| project timestamp = TimeGenerated, rule = AlertName, host = tostring(e.HostName)
```

```spl
index=notable earliest="10/30/2026:09:45:00" latest="10/30/2026:13:00:00"
| eval host=coalesce(dest, src, host)
| table _time rule_name host | rename _time as timestamp, rule_name as rule
```

For EDR-native alerts (Defender `AlertInfo` + `AlertEvidence`, CrowdStrike detections export) include them too; the SOC sees them.

## 3. Score

```bash
python3 scripts/coverage_matrix.py --plan exercise.json --alerts alerts.csv > results.csv
python3 scripts/coverage_matrix.py --plan exercise.json --alerts alerts.csv --format json --fail-under 70
```

| Status | Meaning | Follow-up |
|---|---|---|
| `detected` | An expected rule fired on that host inside the window | Record latency; check alert severity and triage path |
| `detected-other` | Only unexpected rules fired | Either the mapping is wrong or a broad rule caught it; decide which rule should own it |
| `missed` | Nothing fired on that host in the window | Check telemetry first (was the event logged?), then the rule |

Hosts match case-insensitively and ignore DNS suffixes. Epoch seconds/milliseconds and ISO 8601 timestamps are accepted; naive timestamps are treated as UTC. Summary on stderr: counts, detected percentage, median latency.

## 4. Diagnose misses in order

1. **Telemetry:** did the raw event arrive (Sysmon/EDR event, process creation with command line)? If not, it is a logging gap (see `log-source-onboarding`).
2. **Parsing/normalization:** the field the rule uses is empty or renamed.
3. **Rule logic:** the procedure variant evades the rule (e.g., `comsvcs.dll` MiniDump instead of `procdump`).
4. **Pipeline:** rule disabled, schedule window too short, suppression or allow-list hid it, alert below the severity forwarded to the queue.

## 5. Report

```markdown
# Detection validation: <exercise>  Date: <date>
Procedures executed: 40 on 6 hosts   Detected: 26 (65%)   Other-rule: 5   Missed: 9
Median latency: 4 min (p90 22 min)
| Technique | Procedure | Status | Rule | Latency | Root cause of miss | Owner | Due |
```

Feed `detected` results with dates back into the ATT&CK coverage layer as **tested** coverage; keep everything else as claimed or none.

## Related skills

`detection-testing`, `purple-team-exercise`, `attack-coverage-mapping`, `attack-simulation-safety`, `detection-coverage-metrics`, `bas-results-review`

## References

- MITRE ATT&CK: https://attack.mitre.org/
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- MITRE Caldera: https://caldera.mitre.org/
- Microsoft Sentinel SecurityAlert table: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityalert
