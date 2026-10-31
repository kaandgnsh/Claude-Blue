---
name: credential-theft-detection
description: Detect and investigate Windows credential theft — LSASS memory access and dumping (Mimikatz, comsvcs MiniDump, procdump), SAM/SECURITY/NTDS.dit extraction, DPAPI and browser credential theft — and harden against it (Credential Guard, RunAsPPL). Use when an alert mentions LSASS, credential dumping, or after confirmed hands-on-keyboard activity.
license: MIT
metadata:
  category: windows-security
  version: "2.0.0"
  verification: documented
---

# Credential Theft Detection (Windows)

## Techniques and telemetry

| Technique | ATT&CK | Signals |
|---|---|---|
| LSASS memory dump | T1003.001 | Sysmon 10 `TargetImage=...\lsass.exe` with `GrantedAccess` incl. `0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1fffff`; `rundll32.exe comsvcs.dll, MiniDump`; `procdump -ma lsass`; `.dmp` file created by unusual process (Sysmon 11); Task Manager "Create dump file" |
| SAM/SECURITY hive | T1003.002 | `reg save HKLM\SAM`, `reg save HKLM\SECURITY`; Volume Shadow Copy access |
| NTDS.dit | T1003.003 | `ntdsutil "ac i ntds" "ifm" "create full"`, `vssadmin create shadow` on DC, `esentutl /y /vss` |
| DCSync | T1003.006 | See `dcsync-detection` |
| LSA secrets / cached creds | T1003.004/.005 | SECURITY hive access |
| DPAPI / browser creds | T1555.003, T1555.004 | Non-browser process reading `Login Data`/`Local State`; `vaultcmd` |

## Queries

MDE / Sentinel:
```kusto
DeviceProcessEvents
| where ProcessCommandLine has_all ("comsvcs", "MiniDump") or
        (FileName =~ "procdump.exe" or ProcessVersionInfoOriginalFileName =~ "procdump") and ProcessCommandLine has "lsass"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```
Splunk (Sysmon):
```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
  NOT SourceImage IN ("*\\MsMpEng.exe","*\\csrss.exe","*\\wininit.exe","*\\svchost.exe")
| stats count values(GrantedAccess) by host, SourceImage
```
Tune the `SourceImage` allow-list per environment (EDR, backup, monitoring agents legitimately open LSASS); verify full path and signer.

## Sigma (comsvcs MiniDump)

```yaml
title: LSASS Dump via Comsvcs MiniDump
id: 6a3d6c2e-1b7a-4c7e-9a8e-2f3a1b5c7d90
status: stable
description: Detects rundll32 invoking comsvcs.dll MiniDump, commonly used to dump LSASS memory.
author: Claude-Blue
date: 2026-10-31
tags:
  - attack.credential-access
  - attack.t1003.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - 'comsvcs'
      - 'MiniDump'
  condition: selection
falsepositives:
  - Unlikely
level: high
```

## Response

1. Treat as credential compromise of **every account with a session on the host** since the dump time (interactive, RDP, services, scheduled tasks).
2. Preserve the dump file location and process evidence; acquire memory if still live.
3. Reset passwords / revoke sessions for exposed accounts; if a DA session existed, escalate to AD-wide response (`ad-privileged-access-review`).

## Hardening

Credential Guard (VBS), LSA protection (`RunAsPPL=1`), disable WDigest, Defender ASR rule "Block credential stealing from LSASS", restrict debug privilege (`SeDebugPrivilege`), Protected Users group for admins, tiered admin model.

## Related skills

`dcsync-detection`, `memory-forensics`, `sysmon-deployment`, `kerberos-attack-detection`

## References

- MITRE ATT&CK T1003: https://attack.mitre.org/techniques/T1003/
- Microsoft: Configure added LSA protection: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
- Microsoft Credential Guard: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
- ASR rules reference: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
