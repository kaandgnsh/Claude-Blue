---
name: windows-artifacts
description: Analyze Windows execution, file-access and user-activity artefacts — Prefetch, Amcache, ShimCache, SRUM, LNK, Jump Lists, ShellBags, $MFT, $UsnJrnl, Recycle Bin, browser history — with Eric Zimmerman's tools. Use when proving program execution, file access or user activity on a Windows system from a disk image or triage collection.
license: MIT
metadata:
  category: dfir
  version: "2.0.0"
  verification: documented
---

# Windows Forensic Artefacts

## Which artefact proves what

| Artefact | Location | Proves | Caveats |
|---|---|---|---|
| Prefetch | `C:\Windows\Prefetch\*.pf` | Execution, run count, last 8 run times (Win8+), files referenced | Disabled by default on many servers; SSD-based workstations still usually on |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | Presence & SHA1 of executables; often execution | Not definitive proof of execution by itself |
| ShimCache (AppCompatCache) | `SYSTEM` hive | File existed/was examined; order of entries | Win10+: no execution flag; written at shutdown |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | Per-app network bytes, energy, 30–60 days | Hourly aggregation |
| BAM/DAM | `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` | Last execution per user | Win10 1709+; short retention |
| LNK files | `%APPDATA%\Microsoft\Windows\Recent\` | File/folder opened, target MAC times, volume serial, often source host | |
| Jump Lists | `...\Recent\AutomaticDestinations\` | Per-app recently opened files | |
| ShellBags | `NTUSER.DAT`, `UsrClass.dat` | Folders browsed (incl. removable/network) | |
| $MFT / $UsnJrnl / $LogFile | NTFS metadata | File create/rename/delete history | USN rolls over |
| Event logs | `C:\Windows\System32\winevt\Logs\` | Logons, services, tasks, PowerShell | See `windows-event-log-analysis` |
| Recycle Bin | `C:\$Recycle.Bin\<SID>\$I*` | Deleted file original path & time | |
| Browser | Chrome/Edge `History` SQLite, Firefox `places.sqlite` | Downloads, visited URLs | |

## Parsing commands (Eric Zimmerman tools, .NET)

```powershell
PECmd.exe -d E:\C\Windows\Prefetch --csv out\ --csvf prefetch.csv
AmcacheParser.exe -f E:\C\Windows\AppCompat\Programs\Amcache.hve --csv out\
AppCompatCacheParser.exe -f E:\C\Windows\System32\config\SYSTEM --csv out\
SrumECmd.exe -f E:\C\Windows\System32\sru\SRUDB.dat -r E:\C\Windows\System32\config\SOFTWARE --csv out\
LECmd.exe -d E:\C\Users --csv out\
JLECmd.exe -d E:\C\Users --csv out\
SBECmd.exe -d E:\C\Users --csv out\
MFTECmd.exe -f E:\C\$MFT --csv out\ --csvf mft.csv
MFTECmd.exe -f E:\C\$Extend\$J --csv out\ --csvf usn.csv
EvtxECmd.exe -d E:\C\Windows\System32\winevt\Logs --csv out\ --csvf evtx.csv
RBCmd.exe -d E:\C\$Recycle.Bin --csv out\
```
Collect hives with their transaction logs (`.LOG1/.LOG2`) so tools can replay dirty hives. KAPE (`!SANS_Triage` target, `!EZParser` module) automates collection + parsing.

## Workflow

1. Start from a lead (file name, time, user). Search Prefetch/Amcache/ShimCache for the binary.
2. Establish execution time from Prefetch/BAM/4688/Sysmon 1; establish *who* from BAM SID, LNK/Jump Lists, logon sessions.
3. Find the file's origin: `$MFT` creation, Zone.Identifier ADS (`HostUrl`), browser downloads, LNK source volume.
4. Check exfil indicators: SRUM network bytes per app, archive tools (7z/rar) in Prefetch, cloud sync clients.
5. Feed everything into `timeline-analysis`.

## Related skills

`registry-analysis`, `timeline-analysis`, `windows-event-log-analysis`, `velociraptor-collection`

## References

- Eric Zimmerman tools: https://ericzimmerman.github.io/
- SANS Windows Forensic Analysis poster: https://www.sans.org/posters/windows-forensic-analysis/
- KAPE: https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape
