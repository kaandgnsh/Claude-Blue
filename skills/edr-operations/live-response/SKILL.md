---
name: live-response
description: Use EDR live response / remote shell (Defender Live Response, Falcon RTR, SentinelOne RemoteOps) safely to collect files, memory, process lists and artefacts or to perform approved remediation, with full command logging. Use when remote hands-on collection from an endpoint is needed during an investigation.
license: MIT
metadata:
  category: edr-operations
  version: "2.0.0"
  verification: documented
---

# EDR Live Response

Live response is privileged remote code execution on production endpoints. Treat every session as an evidence-bearing, audited change.

## Before connecting

- Authorization: case ID, approver for any non-read-only action.
- Plan: list exact commands/scripts; prefer read-only collection first.
- Check host role (DC, database, OT gateway) and business hours impact.
- Confirm the session is logged by the platform (Defender: Action center; Falcon: RTR audit; S1: activity log).

## Typical collection commands

Defender for Endpoint Live Response:
```
processes
connections
getfile "C:\Users\alice\AppData\Local\Temp\payload.exe"
run collect_triage.ps1          # script must be uploaded to the library first
```
CrowdStrike RTR:
```
ps
netstat
get C:\Windows\Prefetch\PAYLOAD.EXE-1A2B3C4D.pf
memdump <pid> C:\Windows\Temp\pid.dmp     (admin RTR)
```
Exact command availability and permission tiers differ by product/role — check vendor documentation.

## Rules

1. Collect volatile data first (process list, connections, memory of suspect PIDs).
2. Never browse or execute attacker files interactively; retrieve them hashed to the platform's quarantine/collection store.
3. Remediation (kill process, delete file, registry change) only with approval and after collection; record before/after state.
4. Paste every command and its output timestamp into the case log.
5. Close the session; verify no leftover tools or files remain on the host.

## Output

`Session <id> | host | analyst | start/end UTC | commands (verbatim) | files retrieved + sha256 | actions with approval reference`

## Related skills

`edr-alert-investigation`, `host-isolation`, `velociraptor-collection`, `evidence-intake`

## References

- Microsoft Defender for Endpoint live response: https://learn.microsoft.com/en-us/defender-endpoint/live-response
- CrowdStrike / SentinelOne live response docs (vendor portals)
