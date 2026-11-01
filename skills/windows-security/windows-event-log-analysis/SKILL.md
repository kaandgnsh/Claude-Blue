---
name: windows-event-log-analysis
description: Investigate Windows Security, System, PowerShell, Sysmon, RDP, Task Scheduler and Defender event logs — logons, process creation, service/task installs, account changes, log clearing — with Get-WinEvent, Hayabusa, Chainsaw or SIEM queries. Use when analysing EVTX files or Windows events in a SIEM during triage, hunting or forensics.
license: MIT
metadata:
  category: windows-security
  version: "2.2.0"
  verification: documented
---

# Windows Event Log Analysis

## Key event IDs

The most used IDs are below. The full reference (logon types, 4625 status codes, account and directory changes, share and WFP events, tampering, all Sysmon IDs, required audit subcategories) is in [references/event-ids.md](references/event-ids.md); read it when an ID or code is not in this table.

| ID | Log | Meaning | Notes |
|---|---|---|---|
| 4624 / 4625 | Security | Logon success / failure | `LogonType`: 2 interactive, 3 network, 4 batch, 5 service, 7 unlock, 8 network cleartext, 9 new credentials (runas /netonly), 10 RemoteInteractive (RDP), 11 cached |
| 4648 | Security | Logon with explicit credentials | runas, lateral tools |
| 4672 | Security | Special privileges assigned to logon | Admin-equivalent logon |
| 4688 | Security | Process creation | Enable "Include command line in process creation events" |
| 4697 / 7045 | Security / System | Service installed | PsExec, malware persistence |
| 4698 / 4702 | Security | Scheduled task created / updated | Also TaskScheduler/Operational 106, 140, 200/201 |
| 4720, 4722, 4724, 4738 | Security | Account created, enabled, password reset, changed | |
| 4728 / 4732 / 4756 | Security | Member added to global / local / universal group | Privileged group changes |
| 4740 | Security | Account locked out | Spray / brute force |
| 4768 / 4769 / 4771 / 4776 | Security (DC) | TGT, service ticket, pre-auth failure, NTLM validation | See `kerberos-attack-detection` |
| 1102 / 104 | Security / System | Audit log cleared | High fidelity |
| 4104 | PowerShell/Operational | Script block logging | See `powershell-logging` |
| 21, 24, 25 | TerminalServices-LocalSessionManager | RDP session logon/disconnect/reconnect | Source IP recorded |
| 1149 | TerminalServices-RemoteConnectionManager | RDP network authentication succeeded | |
| 5861 | WMI-Activity/Operational | Permanent WMI event subscription | Persistence |
| 1116 / 1117 / 5001 / 5007 | Windows Defender/Operational | Detection, action, RT protection disabled, config changed | Tampering |

## Querying

```powershell
# Last 24h RDP logons
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-1)} |
  Where-Object { $_.Properties[8].Value -eq 10 } |
  Select-Object TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='SrcIP';e={$_.Properties[18].Value}}

# Offline EVTX
Get-WinEvent -Path .\Security.evtx -FilterXPath "*[System[(EventID=1102)]]"
```
(Property indexes depend on event version; verify with `$_.ToXml()` before relying on them.)

Bulk triage of EVTX directories with Sigma-based tools:

```sh
hayabusa csv-timeline -d ./evtx -o hayabusa.csv
chainsaw hunt ./evtx -s ./sigma/rules --mapping ./mappings/sigma-event-logs-all.yml --csv --output ./chainsaw
```

Sentinel (`SecurityEvent`): `SecurityEvent | where EventID == 4625 | summarize fails=count(), users=dcount(TargetUserName) by IpAddress, bin(TimeGenerated, 1h) | where users > 10`

Splunk (Windows TA): `index=wineventlog EventCode=4624 Logon_Type=10 | stats count by src_ip, user, dest`

## Analysis tips

- Correlate by **Logon ID** (`TargetLogonId` in 4624 ↔ `SubjectLogonId` in 4688/4672) to tie processes to the logon that spawned them.
- Network logons (type 3) from workstations to many other workstations = lateral movement candidate.
- Absence of events: check audit policy (`auditpol /get /category:*`) and log size/retention before concluding.
- 4625 `Status`/`SubStatus`: `0xC000006A` bad password, `0xC0000064` user doesn't exist, `0xC0000234` locked out, `0xC0000072` disabled (all codes in the reference file).

## Related skills

`sysmon-deployment`, `powershell-logging`, `lateral-movement-detection`, `kerberos-attack-detection`, `windows-artifacts`

## References

- Microsoft security auditing event reference: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/security-auditing-overview
- Hayabusa: https://github.com/Yamato-Security/hayabusa
- Chainsaw: https://github.com/WithSecureLabs/chainsaw
- Microsoft audit policy recommendations: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations
