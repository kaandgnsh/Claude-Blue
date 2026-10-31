---
name: velociraptor-collection
description: Use Velociraptor for live endpoint triage collection and fleet-wide hunts — offline collectors, KapeFiles targets, VQL queries, process/YARA scans and event log hunting. Use when you need forensic artefacts from many endpoints quickly, or when EDR lacks the needed visibility.
license: MIT
metadata:
  category: dfir
  version: "2.0.0"
  verification: documented
---

# Velociraptor Collection and Hunting

## Deployment modes

- **Server + clients**: persistent agents for fleet hunts (`velociraptor --config server.config.yaml frontend`).
- **Offline collector**: a self-contained executable that collects selected artefacts to a ZIP — built in the GUI (Server Artifacts → `Server.Utils.CreateCollector`) — ideal for isolated hosts or third parties.
- **Local**: `velociraptor artifacts collect Windows.System.Pslist --format json` for one-off use.

## Core artefacts

| Need | Artifact |
|---|---|
| Triage file collection | `Windows.KapeFiles.Targets` (e.g. `_SANS_Triage` target) |
| Process list / tree | `Windows.System.Pslist`, `Generic.System.Pstree` |
| Network connections | `Windows.Network.Netstat` |
| Event log search | `Windows.EventLogs.EvtxHunter` (IOC regex across all EVTX) |
| Persistence | `Windows.Sys.StartupItems`, `Windows.System.TaskScheduler`, `Windows.Persistence.PermanentWMIEvents`, `Windows.System.Services` |
| Execution | `Windows.Forensics.Prefetch`, `Windows.Detection.Amcache` |
| YARA | `Windows.Detection.Yara.Process`, `Generic.Detection.Yara.Glob` |
| Linux | `Linux.Sys.Pslist`, `Linux.Sys.BashHistory`, `Linux.Sys.Crontab`, `Linux.Ssh.AuthorizedKeys` |

Artifact names evolve between releases; confirm in your server's artifact list.

## VQL examples

```sql
-- Processes whose binary is in a user-writable path
SELECT Pid, Ppid, Name, Exe, CommandLine FROM pslist()
WHERE Exe =~ '(?i)\\\\(AppData|Temp|Users\\\\Public)\\\\'

-- Files dropped in the last 24h under ProgramData
SELECT OSPath, Size, Mtime FROM glob(globs='C:/ProgramData/**/*.exe')
WHERE Mtime > now() - 86400
```

## Hunt workflow

1. Define the question and IOC/TTP; pick or write the artifact; test on 1–3 hosts.
2. Set a resource budget (CPU limit, max rows/bytes, timeout) — hunts across thousands of hosts can hurt production.
3. Launch to a labelled subset first (e.g., `label:servers`), review, then expand.
4. Post-process with notebooks; export results with hashes to the case.

## Safety

Collection requires incident authorization; scope hunts with labels; avoid unbounded globs (`C:/**`) on production servers; protect the server's API/admin interface (it is effectively remote code execution on every endpoint).

## Related skills

`osquery-investigation`, `windows-artifacts`, `incident-scoping`, `live-response`

## References

- Velociraptor docs: https://docs.velociraptor.app/
- Artifact exchange: https://docs.velociraptor.app/exchange/
