---
name: mdm-compliance-review
description: Review mobile and endpoint management (Intune, Jamf, Workspace ONE, Google endpoint management) posture — enrollment coverage, compliance policies (OS version, encryption, passcode, jailbreak/root), app protection policies for BYOD, conditional access integration, configuration profiles, and stale/non-compliant device handling. Use when assessing MDM effectiveness, onboarding BYOD, or investigating why non-compliant devices accessed corporate data.
license: MIT
metadata:
  category: mobile-security
  version: "2.0.0"
  verification: documented
---

# MDM Compliance Review

## Coverage

Devices accessing corporate apps (from IdP sign-in logs: device IDs, OS) vs. enrolled/managed devices — the difference is unmanaged access. Entra example:
```kusto
SigninLogs
| where TimeGenerated > ago(30d) and ResultType == "0"
| extend os = tostring(DeviceDetail.operatingSystem), managed = tostring(DeviceDetail.isManaged), compliant = tostring(DeviceDetail.isCompliant)
| summarize users=dcount(UserPrincipalName), signins=count() by os, managed, compliant
```

## Compliance policy baseline

| Setting | iOS/iPadOS | Android Enterprise | macOS/Windows |
|---|---|---|---|
| Minimum OS | Supported versions; block N-2 or older | Security patch level ≤ 90 days old | Supported builds |
| Encryption | Default with passcode | Required | FileVault / BitLocker |
| Passcode | 6+ digits, auto-lock | Same | Login password policy |
| Jailbreak/root | Block | Play Integrity / attestation | — |
| Threat defense | MTD integration (Defender, Lookout) risk ≤ low | Same | EDR healthy |
| Action on non-compliance | Grace period then block via Conditional Access, notify user | Same | Same |

## BYOD

App protection policies (MAM without enrollment): require PIN/biometrics for managed apps, block copy/paste to unmanaged apps, prevent backup of org data, selective wipe; Conditional Access "require app protection policy".

## Hygiene

Stale devices (no check-in 30–90 days) retired; corporate-owned devices supervised/fully managed; configuration profiles reviewed for risky settings (custom root CAs, VPN/proxy profiles); lost-device process (remote lock/wipe) tested.

## Output

`Platform | Enrolled | Compliant % | Unmanaged access (users/sign-ins) | Policy gaps | Stale devices | Actions`

## Related skills

`endpoint-hardening`, `conditional-access-review`, `mobile-compromise-triage`, `macos-triage`

## References

- Microsoft Intune device compliance: https://learn.microsoft.com/en-us/intune/intune-service/protect/device-compliance-get-started
- Intune app protection policies: https://learn.microsoft.com/en-us/intune/intune-service/apps/app-protection-policy
- NIST SP 800-124 Rev. 2 Guidelines for Managing the Security of Mobile Devices: https://csrc.nist.gov/pubs/sp/800/124/r2/final
