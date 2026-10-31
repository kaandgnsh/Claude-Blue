---
name: detection-testing
description: Test detections with adversary emulation and replayed data — Atomic Red Team, MITRE Caldera, recorded attack datasets (OTRF Security-Datasets, Splunk attack_data), positive/negative unit cases — and record pass/fail with telemetry evidence. Use when validating a new or changed detection, running a detection regression suite, or proving coverage for an ATT&CK technique.
license: MIT
metadata:
  category: detection-engineering
  version: "2.0.0"
  verification: documented
---

# Detection Testing

## Test levels

| Level | Method | Proves |
|---|---|---|
| Unit | Rule vs. stored positive/negative events | Logic correct |
| Replay | Ingest recorded attack data (Security-Datasets, attack_data) into a test index | Parsing + logic |
| Emulation | Execute technique in a lab or approved test host (Atomic Red Team, Caldera) | End-to-end: telemetry → pipeline → rule → alert |
| Purple team | Operator-driven scenario | Detection + response process |

## Atomic Red Team (lab or approved test hosts only)

```powershell
Install-Module -Name invoke-atomicredteam -Scope CurrentUser
Import-Module invoke-atomicredteam
Invoke-AtomicTest T1003.001 -ShowDetailsBrief      # list tests
Invoke-AtomicTest T1003.001 -TestNumbers 1 -CheckPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 1          # execute
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup # always clean up
```
Record exact test GUID, host, time (UTC), and user.

## Procedure

1. Choose tests that exercise the rule's logic **and** realistic variations (renamed binary, different flags, alternate parent).
2. Confirm telemetry arrives (raw event visible) before judging the rule.
3. Check rule fired within expected latency; capture alert ID.
4. Run a benign negative case (e.g., normal admin usage) to confirm no alert.
5. Log result: pass / fail-no-telemetry / fail-logic / fail-pipeline.

## Results log

```
Rule <id> | Test <technique/GUID/variation> | Host | Time UTC | Telemetry seen (y/n, event id) | Alert (y/n, id, latency) | Result | Notes
```

## Safety

Run emulation only on systems authorized in writing, never on production DCs or customer systems without change approval; prefer isolated lab tenants. Some atomics modify security settings — always run `-Cleanup` and verify.

## Related skills

`detection-as-code`, `attack-coverage-mapping`, `detection-coverage-metrics`, `hunt-to-detection`

## References

- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- Invoke-AtomicRedTeam: https://github.com/redcanaryco/invoke-atomicredteam
- MITRE Caldera: https://caldera.mitre.org/
- OTRF Security-Datasets: https://github.com/OTRF/Security-Datasets
- Splunk attack_data: https://github.com/splunk/attack_data
