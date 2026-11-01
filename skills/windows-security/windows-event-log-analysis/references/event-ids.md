# Windows event ID reference

Loaded on demand by `windows-event-log-analysis`. Grouped by investigation question. "Audit" names the advanced audit policy subcategory that must be enabled for Security log events.

## Logon and authentication

| ID | Log | Meaning | Audit / notes |
|---|---|---|---|
| 4624 | Security | Successful logon | Logon / `LogonType`, `IpAddress`, `LogonProcessName`, `AuthenticationPackageName`, `TargetLogonId`, `ElevatedToken` |
| 4625 | Security | Failed logon | Logon / see status codes below |
| 4634 / 4647 | Security | Logoff / user-initiated logoff | Logoff / pair with 4624 by `TargetLogonId` for session duration |
| 4648 | Security | Logon with explicit credentials | Logon / runas, `net use /user`, many lateral tools |
| 4672 | Security | Special privileges assigned | Special Logon / admin-equivalent session |
| 4964 | Security | Special groups assigned to new logon | Special Logon / needs configured special groups |
| 4768 | Security (DC) | Kerberos TGT requested | Kerberos Authentication Service / `TicketEncryptionType` 0x17 = RC4 |
| 4769 | Security (DC) | Kerberos service ticket requested | Kerberos Service Ticket Operations / Kerberoasting: RC4 tickets for user SPNs |
| 4771 | Security (DC) | Kerberos pre-authentication failed | Kerberos Authentication Service / failure code 0x18 = bad password |
| 4776 | Security (DC/host) | NTLM credential validation | Credential Validation / `Status` like 4625 |
| 4740 | Security (DC) | Account locked out | User Account Management / `CallerComputerName` = source |
| 4778 / 4779 | Security | RDP session reconnected / disconnected | Other Logon/Logoff Events |
| 21 / 24 / 25 | TerminalServices-LocalSessionManager/Operational | RDP logon / disconnect / reconnect | Source IP in event data |
| 1149 | TerminalServices-RemoteConnectionManager/Operational | RDP network authentication succeeded | Recorded before logon; useful when 4624 rolled over |
| 4800 / 4801 | Security | Workstation locked / unlocked | Other Logon/Logoff Events |

### Logon types (4624/4625 `LogonType`)

| Type | Meaning | Typical source |
|---|---|---|
| 2 | Interactive | Console, `runas` without `/netonly` |
| 3 | Network | SMB, WinRM, `net use`, PsExec authentication |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Service start under an account |
| 7 | Unlock | Screen unlock |
| 8 | NetworkCleartext | IIS basic auth, PowerShell with CredSSP |
| 9 | NewCredentials | `runas /netonly`, some pass-the-hash tooling |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Domain logon with cached credentials (offline) |

### 4625 / 4776 status and sub-status codes

| Code | Meaning |
|---|---|
| 0xC0000064 | User name does not exist (spraying invalid names) |
| 0xC000006A | Correct user, wrong password |
| 0xC000006D | Generic logon failure (check sub-status) |
| 0xC000006F | Logon outside allowed hours |
| 0xC0000070 | Workstation restriction |
| 0xC0000071 | Password expired |
| 0xC0000072 | Account disabled |
| 0xC0000193 | Account expired |
| 0xC0000224 | Password must change at next logon |
| 0xC0000234 | Account locked out |
| 0xC000015B | Logon type not granted (e.g., deny network logon) |
| 0xC0000413 | Authentication firewall (selective authentication) blocked |

## Process, service and task execution

| ID | Log | Meaning | Audit / notes |
|---|---|---|---|
| 4688 | Security | Process created | Process Creation + "Include command line" GPO / `ParentProcessName` on Windows 10+ |
| 4689 | Security | Process exited | Process Termination |
| 4697 | Security | Service installed | Security System Extension |
| 7045 | System | Service installed | Always on; PsExec `PSEXESVC`, random service names |
| 7034 / 7036 / 7040 | System | Service crashed / state change / start type changed | Disabling of security services |
| 4698 / 4699 / 4700 / 4701 / 4702 | Security | Task created / deleted / enabled / disabled / updated | Other Object Access Events / full task XML in event |
| 106 / 140 / 141 / 200 / 201 | TaskScheduler/Operational | Task registered / updated / deleted / action started / completed | Not enabled by default on all versions |
| 4103 / 4104 | PowerShell/Operational | Module logging / script block logging | 4104 level Warning = suspicious content auto-logged |
| 400 / 600 | Windows PowerShell | Engine start (with `HostApplication`) / provider start | Downgrade to v2: `EngineVersion=2.0` |
| 5857 / 5860 / 5861 | WMI-Activity/Operational | Provider loaded / temporary / permanent subscription | 5861 = WMI persistence |
| 3 / 59 / 60 | Bits-Client/Operational | BITS job created / transfer started / stopped | BITS abuse for download and persistence |

## Account and group changes

| ID | Meaning | Notes |
|---|---|---|
| 4720 / 4726 | User created / deleted | User Account Management |
| 4722 / 4725 | User enabled / disabled | |
| 4723 / 4724 | Password change attempt / reset by another account | Reset by help desk vs. attacker |
| 4738 | User account changed | `UserAccountControl` changes, e.g., "Don't require preauth" (AS-REP roasting) |
| 4781 | Account renamed | |
| 4767 | Account unlocked | |
| 4728 / 4729 | Member added / removed, global security group | Domain Admins, Enterprise Admins |
| 4732 / 4733 | Member added / removed, local (domain local) group | Local Administrators, Remote Desktop Users |
| 4756 / 4757 | Member added / removed, universal group | |
| 4794 | DSRM administrator password set attempt | DC persistence |
| 4765 / 4766 | SID History added / failed | SID history injection |
| 5136 | Directory object modified | Directory Service Changes + SACL; GPO, AdminSDHolder, `msDS-KeyCredentialLink` (shadow credentials) |
| 4662 | Operation on a directory object | DS Access + SACL; DCSync = replication GUIDs `1131f6aa-…`, `1131f6ad-…` |

## Object access and network

| ID | Meaning | Notes |
|---|---|---|
| 5140 | Network share accessed | File Share; `ADMIN$`, `C$`, `IPC$` from workstations |
| 5145 | Share object access check | Detailed File Share; noisy, filter by share and file name |
| 4663 | Object access attempt | File System + SACL; ransomware mass access |
| 4656 | Handle requested | LSASS handle requests (with SACL on lsass) |
| 5156 / 5157 | WFP allowed / blocked connection | Filtering Platform Connection; high volume |
| 5152 | WFP dropped packet | |

## Tampering and defense evasion

| ID | Log | Meaning |
|---|---|---|
| 1102 | Security | Security log cleared |
| 104 | System | Other event log cleared |
| 4719 | Security | System audit policy changed |
| 4906 / 4907 | Security | CrashOnAuditFail changed / SACL changed |
| 4616 | Security | System time changed |
| 1116 / 1117 | Windows Defender/Operational | Malware detected / action taken |
| 5001 | Windows Defender/Operational | Real-time protection disabled |
| 5007 | Windows Defender/Operational | Configuration changed (exclusions added) |
| 5013 | Windows Defender/Operational | Tamper protection blocked a change |
| 3077 / 3089 | CodeIntegrity/Operational | WDAC enforced block / signature details |
| 8004 | AppLocker/EXE and DLL | AppLocker block |

## Sysmon event IDs

| ID | Meaning | ID | Meaning |
|---|---|---|---|
| 1 | Process creation (hashes, command line, parent) | 15 | File stream created (ADS, Zone.Identifier) |
| 2 | File creation time changed (timestomping) | 16 | Sysmon configuration changed |
| 3 | Network connection | 17 / 18 | Named pipe created / connected |
| 4 | Sysmon service state changed | 19 / 20 / 21 | WMI filter / consumer / binding |
| 5 | Process terminated | 22 | DNS query |
| 6 | Driver loaded | 23 | File delete archived |
| 7 | Image (DLL) loaded | 24 | Clipboard change |
| 8 | CreateRemoteThread | 25 | Process tampering (hollowing, herpaderping) |
| 9 | RawAccessRead (direct disk read) | 26 | File delete logged (not archived) |
| 10 | ProcessAccess (LSASS access) | 27 | File block executable |
| 11 | File created | 28 | File block shredding |
| 12 / 13 / 14 | Registry create-delete / value set / rename | 29 | File executable detected |
| 255 | Sysmon error | | |

## Sources

- Microsoft advanced security audit policy and event reference: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-audit-policy-settings
- Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Microsoft Defender Antivirus event IDs: https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
