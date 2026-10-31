---
name: lolbin-hunt
description: Hunt for abuse of living-off-the-land binaries and scripts (LOLBAS/GTFOBins) — certutil, mshta, rundll32, regsvr32, bitsadmin, msbuild, wmic, installutil, curl, and Linux equivalents — using command-line patterns, parentage and network activity. Use when hunting fileless or signed-binary proxy execution, or when an alert involves a Microsoft-signed binary doing something unusual.
license: MIT
metadata:
  category: threat-hunting
  version: "2.0.0"
  verification: documented
---

# LOLBin Hunt

## High-signal patterns (Windows)

| Binary | Suspicious usage | ATT&CK |
|---|---|---|
| `certutil.exe` | `-urlcache -split -f http...`, `-decode`, `-decodehex` | T1105, T1140 |
| `mshta.exe` | URL or `javascript:`/`vbscript:` argument; child of Office/browser | T1218.005 |
| `rundll32.exe` | DLL in user-writable path; `javascript:`; no export name; network connections | T1218.011 |
| `regsvr32.exe` | `/s /n /u /i:http...scrobj.dll` (Squiblydoo) | T1218.010 |
| `bitsadmin.exe` | `/transfer` / `/addfile` with remote URL | T1197 |
| `msbuild.exe` | Building a project from `Temp`/`Users` with inline tasks | T1127.001 |
| `installutil.exe`, `regasm.exe`, `regsvcs.exe` | Running assemblies from user paths | T1218.004/.009 |
| `wmic.exe` | `process call create`, `/node:`, XSL (`/format:http`) | T1047, T1220 |
| `cmstp.exe` | `/s /ns` with INF from user path | T1218.003 |
| `forfiles.exe`, `pcalua.exe` | Indirect command execution | T1202 |
| `esentutl.exe` | Copying locked files (`/vss`) like NTDS/SAM/browser DBs | T1003 |
| `curl.exe` / `tar.exe` (built-in on Win10+) | Downloads to `%TEMP%`, archive extraction of payloads | T1105 |

Linux (GTFOBins): `curl|wget ... | sh`, `python -c 'import pty...'`, `bash -i >& /dev/tcp/`, `nc -e`, `openssl s_client` reverse shells, `base64 -d | sh`.

## Queries

Sentinel (MDE):
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("urlcache", "-decode", "verifyctl"))
     or (FileName =~ "mshta.exe" and ProcessCommandLine has_any ("http", "javascript:", "vbscript:"))
     or (FileName =~ "regsvr32.exe" and ProcessCommandLine has_all ("/i:", "scrobj"))
     or (FileName =~ "rundll32.exe" and ProcessCommandLine has "javascript:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```
Use `ProcessVersionInfoOriginalFileName` as well as `FileName` to catch renamed copies.

Network attribution: LOLBins making outbound connections (`DeviceNetworkEvents | where InitiatingProcessFileName in~ ("mshta.exe","regsvr32.exe","rundll32.exe","msbuild.exe","certutil.exe")`) are rare in most fleets.

## Triage

Check parent (Office/browser/script host = bad sign), file paths (user-writable), remote URL reputation, and whether the same command appears in IT automation (SCCM, Intune scripts) — document allow-listed admin usage precisely.

## Related skills

`process-tree-analysis`, `application-control`, `stack-counting-hunt`, `sigma-authoring`

## References

- LOLBAS project: https://lolbas-project.github.io/
- GTFOBins: https://gtfobins.github.io/
- MITRE ATT&CK T1218 System Binary Proxy Execution: https://attack.mitre.org/techniques/T1218/
