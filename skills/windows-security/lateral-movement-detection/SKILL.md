---
name: lateral-movement-detection
description: Detect and trace Windows lateral movement — PsExec/service creation, WMI, WinRM/PowerShell remoting, RDP, SMB admin shares, DCOM, scheduled tasks and pass-the-hash/ticket — by correlating source and destination host events. Use when an attacker may be moving between hosts or when mapping the path of a compromise.
license: MIT
metadata:
  category: windows-security
  version: "2.0.0"
  verification: documented
---

# Lateral Movement Detection

Always look at **both ends**: the source host (process launching the remote action) and the destination (logon + resulting process/service).

## Technique → artefacts

| Technique | Source host | Destination host |
|---|---|---|
| PsExec / service exec (T1569.002) | `psexec.exe`, `sc.exe \\host create` | 4624 type 3 → 7045/4697 service (e.g. `PSEXESVC`, random names), 5145 `ADMIN$` write, child of `services.exe` |
| WMI (T1047) | `wmic /node:`, `Invoke-WmiMethod`, `Invoke-CimMethod` | 4624 type 3, process child of `WmiPrvSE.exe` |
| WinRM / PS Remoting (T1021.006) | `Enter-PSSession`, `Invoke-Command`, `winrs` | 4624 type 3, child of `wsmprovhost.exe`, WinRM/Operational 91 |
| RDP (T1021.001) | `mstsc.exe`, Terminal Server Client registry | 4624 type 10, 1149, LocalSessionManager 21/25, `rdpclip.exe` |
| SMB admin shares (T1021.002) | `net use \\host\C$` | 5140/5145 share access, 4624 type 3 |
| Scheduled task remote (T1053.005) | `schtasks /create /s host` | 4698, TaskScheduler 106/200 |
| DCOM (T1021.003) | PowerShell `GetTypeFromProgID(...,"host")` | child of `mmc.exe` / `explorer.exe` via DcomLaunch |
| Pass-the-hash (T1550.002) | — | 4624 type 3, `LogonProcessName=NtLmSsp`, `KeyLength=0`; or type 9 with `seclogo` on source |
| Pass-the-ticket / overpass (T1550.003) | 4768 RC4 from unexpected host | 4624 Kerberos logons not preceded by TGT from that host |

## Queries

Sentinel (MDE) — remote service creation pattern:
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "services.exe"
| where FolderPath has_any (@"\Windows\", @"\ADMIN$") and FileName !in~ ("svchost.exe","msiexec.exe","TrustedInstaller.exe")
| join kind=inner (DeviceLogonEvents | where LogonType == "Network") on DeviceId
| where abs(datetime_diff('second', Timestamp, Timestamp1)) < 120
| project Timestamp, DeviceName, FileName, ProcessCommandLine, RemoteIP, AccountName1
```
Splunk — workstation-to-workstation admin logons (graph source → destinations):
```spl
index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package=NTLM user!="*$" src_ip=10.*
| stats dc(dest) as dests values(dest) by src_ip, user | where dests > 5
```

## Analysis workflow

1. Build a graph of `source → destination` admin logons for compromised accounts (`Logon_Type 3/10` + 4672).
2. For each edge, confirm the execution artefact on the destination (service, WMI child, wsmprovhost child).
3. Order edges in time to reconstruct the path; feed into `incident-scoping`.
4. Baseline: admin jump hosts and management servers (SCCM, RMM) produce legitimate edges — document them.

## Hardening

Tiered admin model, LAPS, deny network logon for local accounts (`SeDenyNetworkLogonRight` for "Local account and member of Administrators group"), host firewall blocking workstation-to-workstation SMB/WinRM/RDP, Restricted Admin/Remote Credential Guard for RDP.

## Related skills

`windows-event-log-analysis`, `credential-theft-detection`, `kerberos-attack-detection`, `incident-scoping`

## References

- MITRE ATT&CK Lateral Movement (TA0008): https://attack.mitre.org/tactics/TA0008/
- JPCERT/CC "Detecting Lateral Movement through Tracking Event Logs": https://www.jpcert.or.jp/english/pub/sr/ir_research.html
