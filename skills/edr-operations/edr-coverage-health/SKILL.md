---
name: edr-coverage-health
description: Measure and fix EDR deployment coverage and sensor health — assets without agents, stale/offline sensors, outdated versions, policies in detect-only mode, tamper protection off, exclusions sprawl. Use for EDR program reviews, before relying on "no EDR telemetry" in an investigation, or after a missed detection.
license: MIT
metadata:
  category: edr-operations
  version: "2.0.0"
  verification: documented
---

# EDR Coverage and Health

## Coverage = assets with healthy, prevention-mode sensors ÷ assets that should have one

Reconcile the EDR device list against an authoritative inventory (CMDB, AD computers, Intune/Jamf, cloud instance inventory, DHCP/NAC). See `asset-inventory-reconciliation`.

## Health checks

| Check | Example |
|---|---|
| Not seen in > 7 days | MDE: `DeviceInfo | summarize last=max(Timestamp) by DeviceId, DeviceName | where last < ago(7d)` |
| Onboarded but no telemetry | Devices present in inventory with zero `DeviceProcessEvents` in 24h |
| Old sensor versions | Group by `ClientVersion`/sensor version; flag N-2 or unsupported |
| Detect-only / passive mode | MDE `Get-MpComputerStatus` `AMRunningMode`; Falcon prevention policy assignment; S1 policy mode |
| Tamper protection off | `IsTamperProtected = False` |
| Exclusions | Export exclusions; flag broad paths (`C:\`, `*.exe`, `%TEMP%`), whole processes like `powershell.exe` |
| Unsupported OS / no agent possible | Legacy, appliances, OT — require compensating network monitoring |
| Linux/container coverage | Often the biggest gap; check servers and Kubernetes nodes |

AD comparison (PowerShell): `Get-ADComputer -Filter 'Enabled -eq $true' -Properties LastLogonTimestamp | Where-Object { [datetime]::FromFileTime($_.LastLogonTimestamp) -gt (Get-Date).AddDays(-30) }` → compare names to EDR export.

## Report

```
EDR coverage <date>
Expected assets: <n>  Healthy prevention-mode: <n> (<%>)
Missing agent: <n> (by OS/business unit)   Stale >7d: <n>   Detect-only: <n>   Tamper off: <n>
Risky exclusions: <list>
Actions: <owner, due>
```

## Related skills

`asset-inventory-reconciliation`, `detection-coverage-metrics`, `log-pipeline-health`, `alert-tuning`

## References

- Microsoft Defender for Endpoint device health reporting: https://learn.microsoft.com/en-us/defender-endpoint/device-health-reports
- CIS Controls v8.1 (Control 10 Malware Defenses): https://www.cisecurity.org/controls
