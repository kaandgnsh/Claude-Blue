---
name: application-control
description: Plan, deploy and monitor application allow-listing — Windows App Control for Business (WDAC), AppLocker, macOS Santa, Linux fapolicyd — including audit-mode rollout, rule design and block-event triage. Use when implementing allow-listing (Essential Eight), investigating blocked executions, or reviewing app-control bypass risk.
license: MIT
metadata:
  category: endpoint-security
  version: "2.0.0"
  verification: documented
---

# Application Control

## Technology choice

| Platform | Technology | Notes |
|---|---|---|
| Windows | **App Control for Business (WDAC)** | Kernel-enforced, supports managed installer & ISG; preferred |
| Windows | AppLocker | Simpler, per-user rules, weaker (not a security boundary per Microsoft) |
| macOS | Santa (North Pole Security fork) | Binary/cert/TeamID rules, sync server |
| Linux | fapolicyd (RHEL), IMA/EVM | Trust database from RPM |

## Rule design principles

- Prefer **publisher/signer + product** rules and **managed installer** (Intune/ConfigMgr) over path rules.
- Path rules only for admin-writable locations (`C:\Program Files\`, `C:\Windows\`), never for user-writable dirs.
- Block known bypass binaries via Microsoft's **recommended block rules** (e.g., `mshta.exe`, `wmic.exe`, `msbuild.exe`, `installutil.exe` where unused).
- Enable script enforcement (PowerShell Constrained Language Mode follows WDAC).

## Rollout

1. Inventory software (`Get-CimInstance Win32_Product` is slow/side-effecting — use Intune/ConfigMgr inventory instead).
2. Create base policy from reference image (WDAC Wizard / `New-CIPolicy -Level Publisher -Fallback Hash -ScanPath C:\`), merge supplemental policies.
3. Deploy in **audit mode**; collect events:
   - WDAC: `Microsoft-Windows-CodeIntegrity/Operational` **3076** (audit would block), **3077** (blocked); MSI/script: `AppLocker/MSI and Script` 8028/8029.
   - AppLocker: 8003 (would block, audit), 8004 (blocked) in `AppLocker/EXE and DLL`.
4. Iterate until audit noise is understood; switch rings to enforce.
5. Operate: exception request process with SLA; monitor blocks centrally.

## Triage of block events

Is it legitimate software missing from policy (→ add publisher rule via change), or an execution attempt from user-writable path / LOLBin (→ investigate as potential malicious activity)?

```kusto
DeviceEvents
| where ActionType startswith "AppControlCodeIntegrityPolicyBlocked" or ActionType startswith "AppControlExecutableBlocked"
| summarize count() by FileName, FolderPath, InitiatingProcessFileName, DeviceName
```
(Action type names vary by product version.)

## Related skills

`endpoint-hardening`, `lolbin-hunt`, `edr-alert-investigation`

## References

- Microsoft App Control for Business: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/
- Microsoft recommended block rules: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol
- Santa: https://northpole.dev/
- ASD Essential Eight application control: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight
