---
name: registry-analysis
description: Examine Windows registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat, Amcache.hve) for persistence, execution, USB devices, user activity, network history and configuration tampering. Use when investigating a Windows host from a disk image or triage collection, or validating suspected registry-based persistence.
license: MIT
metadata:
  category: dfir
  version: "2.0.0"
  verification: documented
---

# Registry Analysis

## Tools

- Registry Explorer / RECmd (Eric Zimmerman): `RECmd.exe -d E:\hives --bn BatchExamples\Kroll_Batch.reb --csv out\` (batch files ship with RECmd; check the current names)
- RegRipper 3: `rip.pl -r NTUSER.DAT -a` (all plugins) or `-p run`
- Live (read-only): `reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"`

Always load transaction logs (`.LOG1/.LOG2`) to get the latest state.

## High-value keys

| Purpose | Key |
|---|---|
| Run persistence | `HKLM|HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `RunOnce`, `...\Policies\Explorer\Run` |
| Winlogon hijack | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` (`Userinit`, `Shell`) |
| IFEO debugger / SilentProcessExit | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>` |
| Services | `HKLM\SYSTEM\CurrentControlSet\Services\<name>` (`ImagePath`, `ServiceDll`, `Start`) |
| AppInit / AppCert DLLs | `...\Windows NT\CurrentVersion\Windows\AppInit_DLLs`, `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls` |
| COM hijack | `HKCU\Software\Classes\CLSID\{...}\InprocServer32` overriding HKLM |
| LSA packages | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` (`Security Packages`, `Notification Packages`, `RunAsPPL`) |
| WDigest cleartext | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` = 1 is suspicious |
| Defender tampering | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` (`DisableAntiSpyware`, `Exclusions\Paths`) |
| RDP | `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server` (`fDenyTSConnections`), `HKCU\Software\Microsoft\Terminal Server Client\Servers` (outbound RDP history) |
| User activity | `NTUSER\...\Explorer\UserAssist` (ROT13), `RecentDocs`, `TypedPaths`, `RunMRU`, `WordWheelQuery` |
| USB devices | `SYSTEM\CurrentControlSet\Enum\USBSTOR`, `SYSTEM\MountedDevices`, `SOFTWARE\Microsoft\Windows Portable Devices\Devices` |
| Networks | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` |
| Timezone / computer name | `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, `...\ComputerName\ComputerName` |

Determine `CurrentControlSet` from `SYSTEM\Select\Current` in offline hives.

## Workflow

1. Record hive source, hash, and the system timezone.
2. Run a batch/plugin pass for breadth; then inspect suspicious keys manually, noting **key last-write time** (key-level only, not per value).
3. Validate each persistence entry: binary exists? signed? path user-writable? present in baseline/golden image?
4. Correlate last-write times with the timeline (4657 registry auditing or Sysmon 12/13/14 if collected).

## Output

`Hive | Key | Value | Data | Last write (UTC) | Assessment | Evidence link`

## Related skills

`windows-artifacts`, `windows-persistence-hunt`, `timeline-analysis`

## References

- RegRipper 3.0: https://github.com/keydet89/RegRipper3.0
- Eric Zimmerman RECmd: https://github.com/EricZimmerman/RECmd
- MITRE ATT&CK T1547.001 Registry Run Keys: https://attack.mitre.org/techniques/T1547/001/
