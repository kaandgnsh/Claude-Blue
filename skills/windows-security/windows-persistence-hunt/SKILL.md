---
name: windows-persistence-hunt
description: Hunt for and validate Windows persistence — Run keys, services, scheduled tasks, WMI event subscriptions, startup folders, IFEO, COM hijacks, LSA/Winlogon, BITS jobs — using Autoruns, PowerShell, EDR and event logs. Use when sweeping hosts after a compromise, hunting for footholds, or verifying eradication.
license: MIT
metadata:
  category: windows-security
  version: "2.0.0"
  verification: documented
---

# Windows Persistence Hunt

## Collection

```powershell
# Sysinternals Autoruns (CLI): all entries, hashes, signature verification, CSV
autorunsc64.exe -accepteula -a * -c -h -s -m -vt:0 > autoruns.csv   # -m hides Microsoft-signed; omit for full picture
# Scheduled tasks with actions
Get-ScheduledTask | ForEach-Object { [pscustomobject]@{Path=$_.TaskPath+$_.TaskName; Author=$_.Author; Action=($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ';'} }
# Services with binary paths
Get-CimInstance Win32_Service | Select-Object Name, StartMode, State, PathName, StartName
# WMI permanent subscriptions
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding
# BITS jobs
Get-BitsTransfer -AllUsers | Select-Object DisplayName, JobState, FileList
```
For fleets use `velociraptor-collection` (`Windows.Sys.StartupItems`, `Windows.Persistence.PermanentWMIEvents`) or `osquery-investigation` (`autoexec`, `scheduled_tasks`, `services`, `wmi_cli_event_consumers`).

## Triage rules for each entry

Flag when **any** holds:
- Binary/script in user-writable path (`\Users\`, `\AppData\`, `\ProgramData\`, `\Temp\`, `\Users\Public\`).
- Unsigned or signer mismatch with claimed vendor; hash not in golden image.
- Interpreter launching inline/encoded content (`powershell -enc`, `mshta`, `rundll32 javascript:`, `regsvr32 /i:http`).
- Names imitating system components (`svch0st`, `WindowsUpdateTask` in a non-Microsoft path).
- Created near the incident window (task XML `RegistrationInfo/Date`, registry last-write, file creation).
- Rare across the fleet (stack-count the entry: present on 1–3 hosts out of thousands).

## Detection events

4697/7045 services, 4698/4702 tasks, Sysmon 12/13 (Run keys), Sysmon 19/20/21 (WMI filter/consumer/binding), WMI-Activity 5861, Sysmon 11 on Startup folder.

## Output

`Host | Mechanism | Location | Command | Signer/Hash | Created/Last-write UTC | Prevalence | Verdict`

## Safety

Export and preserve suspicious entries (task XML, registry export, binary) before removal; removal belongs in the coordinated eradication plan.

## Related skills

`registry-analysis`, `stack-counting-hunt`, `eradication-recovery`, `velociraptor-collection`

## References

- Sysinternals Autoruns: https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- MITRE ATT&CK Persistence (TA0003): https://attack.mitre.org/tactics/TA0003/
