---
name: sysmon-deployment
description: Deploy, tune and validate Microsoft Sysmon — configuration selection (sysmon-modular, SwiftOnSecurity), event coverage, noise reduction, update and health monitoring. Use when planning Windows endpoint telemetry, reviewing a Sysmon config, or troubleshooting missing Sysmon events.
license: MIT
metadata:
  category: windows-security
  version: "2.0.0"
  verification: documented
---

# Sysmon Deployment and Tuning

## Event types that matter most

| ID | Event | Detection value |
|---|---|---|
| 1 | Process create (hashes, command line, parent) | Core execution telemetry |
| 3 | Network connection | Process-attributed connections (filter heavily) |
| 7 | Image loaded | DLL side-loading; noisy — include-list only |
| 8 | CreateRemoteThread | Injection |
| 10 | ProcessAccess | LSASS credential access (`TargetImage` lsass.exe) |
| 11 | FileCreate | Drops in startup/temp paths |
| 12/13/14 | Registry create/set/rename | Persistence keys |
| 15 | FileCreateStreamHash | Zone.Identifier / ADS |
| 17/18 | Pipe created/connected | Cobalt Strike-style named pipes |
| 22 | DNS query | Process-attributed DNS |
| 23 / 26 | FileDelete (archived) / FileDeleteDetected | Wiper / cleanup |
| 25 | ProcessTampering | Hollowing/herpaderping |
| 29 | FileExecutableDetected | New PE written to disk |

## Deployment

```powershell
sysmon64.exe -accepteula -i sysmonconfig.xml   # install
sysmon64.exe -c sysmonconfig.xml               # update config in place
sysmon64.exe -c                                 # print active config
```
Distribute via GPO/Intune/SCCM; log goes to `Microsoft-Windows-Sysmon/Operational`; raise log size (≥ 1 GB on servers) and forward via WEF/agent.

## Config strategy

- Start from **sysmon-modular** (Olaf Hartong; ATT&CK-tagged modules, generates merged configs) or **SwiftOnSecurity sysmon-config** (well-commented baseline).
- Use `RuleName` tags mapping to ATT&CK so SIEM rules can key off them.
- Exclude by **full image path + signer/hash**, never by process name alone; never exclude user-writable paths.
- Event 3/7/22 are the volume drivers; scope them with includes.

## Validation

1. Verify service and driver: `Get-Service Sysmon64`, `fltmc` lists `SysmonDrv`.
2. Generate known activity in a lab (e.g., Atomic Red Team test for T1003.001 against a test host) and confirm events 1/10 appear in the SIEM with expected fields.
3. Monitor health: alert when a host's Sysmon events stop (`Heartbeat`-style query on last event per host) and on event 16 (config change) / 4 (service state change).

## Pitfalls

- Config drift across fleet — track config hash per host (`sysmon64 -c` output or registry `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters`).
- Attackers unload the driver (`fltmc unload SysmonDrv`) — detect via event 255/4 and sudden silence.
- Sysmon complements, not replaces, EDR and Security log auditing.

## Related skills

`windows-event-log-analysis`, `credential-theft-detection`, `log-source-onboarding`, `edr-coverage-health`

## References

- Microsoft Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- sysmon-modular: https://github.com/olafhartong/sysmon-modular
- SwiftOnSecurity sysmon-config: https://github.com/SwiftOnSecurity/sysmon-config
