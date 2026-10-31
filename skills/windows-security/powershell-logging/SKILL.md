---
name: powershell-logging
description: Enable and analyze PowerShell telemetry — script block logging (4104), module logging (4103), transcription, AMSI — to detect encoded commands, download cradles, obfuscation and downgrade attacks. Use when investigating malicious PowerShell, reviewing logging configuration, or writing PowerShell detections.
license: MIT
metadata:
  category: windows-security
  version: "2.0.0"
  verification: documented
---

# PowerShell Logging and Analysis

## Enable (GPO: Administrative Templates → Windows Components → Windows PowerShell)

| Setting | Event | Value |
|---|---|---|
| Turn on PowerShell Script Block Logging | 4104 in `Microsoft-Windows-PowerShell/Operational` | Decoded, deobfuscated script content at execution |
| Turn on Module Logging (`*`) | 4103 | Pipeline execution details |
| Turn on PowerShell Transcription | Text files | Full session I/O; write to a protected share |
| Protected Event Logging (optional) | — | Encrypts 4104 content with a certificate |

PowerShell 5+ automatically logs "suspicious" script blocks at Warning level even without the policy. PowerShell 7 logs to `PowerShellCore/Operational`.

## What to hunt in 4104/4688

- Encoded commands: `-enc`, `-EncodedCommand`, `-e ` with long base64; decode: `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))`.
- Download cradles: `IEX`, `Invoke-Expression`, `DownloadString`, `DownloadFile`, `Net.WebClient`, `Invoke-WebRequest ... | iex`, `Start-BitsTransfer`.
- AMSI bypass strings: `AmsiUtils`, `amsiInitFailed`, `AmsiScanBuffer` patching.
- Defender tampering: `Set-MpPreference -DisableRealtimeMonitoring $true`, `Add-MpPreference -ExclusionPath`.
- Downgrade: `powershell.exe -version 2` (bypasses script block logging; remove the PowerShell v2 feature).
- Credential tools: `Invoke-Mimikatz`, `sekurlsa`, `Get-GPPPassword`, `Invoke-Kerberoast`.
- Large script blocks are split across multiple 4104 events (`MessageNumber`/`MessageTotal`, same `ScriptBlockId`) — reassemble before analysis.

## Queries

Sentinel (MDE): `DeviceProcessEvents | where FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine matches regex @"(?i)\s-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}"`

Splunk: `index=wineventlog source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 (ScriptBlockText="*DownloadString*" OR ScriptBlockText="*AmsiUtils*")`

## Sigma example

```yaml
title: PowerShell Script Block With AMSI Bypass Strings
id: 2b6f0c8e-9d3f-4c55-8c0f-6f1f0a8f3b21
status: experimental
description: Detects script blocks referencing AMSI bypass primitives.
references:
  - https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal
author: Claude-Blue
date: 2026-10-31
tags:
  - attack.defense-impairment
  - attack.t1685
logsource:
  product: windows
  category: ps_script
detection:
  selection:
    ScriptBlockText|contains:
      - 'AmsiUtils'
      - 'amsiInitFailed'
      - 'AmsiScanBuffer'
  condition: selection
falsepositives:
  - Security tooling and research scripts
level: high
```

## Related skills

`script-deobfuscation`, `windows-event-log-analysis`, `sigma-authoring`, `lolbin-hunt`

## References

- Microsoft about_Logging_Windows: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- MITRE ATT&CK T1059.001: https://attack.mitre.org/techniques/T1059/001/
