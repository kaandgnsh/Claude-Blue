---
name: gpo-security-review
description: Review Group Policy for security baseline compliance, dangerous settings, GPP passwords, excessive edit rights and malicious GPO changes; detect GPO-based malware deployment via event 5136. Use when auditing GPOs, comparing to Microsoft/CIS baselines, or investigating ransomware deployed through Group Policy.
license: MIT
metadata:
  category: active-directory-security
  version: "2.0.0"
  verification: documented
---

# GPO Security Review

## Collection

```powershell
Get-GPO -All | Select-Object DisplayName, Id, ModificationTime, GpoStatus
Get-GPOReport -All -ReportType Xml -Path C:\review\gpos.xml
# Who can edit each GPO
Get-GPO -All | ForEach-Object { $g=$_; Get-GPPermission -Guid $g.Id -All |
  Where-Object { $_.Permission -in 'GpoEdit','GpoEditDeleteModifySecurity' } |
  Select-Object @{n='GPO';e={$g.DisplayName}}, Trustee, Permission }
# GPP cpassword remnants (MS14-025)
Select-String -Path "\\$env:USERDNSDOMAIN\SYSVOL\*\Policies\*\*.xml" -Pattern 'cpassword' -List
```
Compare with Microsoft Security Compliance Toolkit baselines using **Policy Analyzer**.

## What to flag

- Non-Tier-0 principals with edit rights on GPOs linked to DCs/Tier 0 OUs (or at domain root).
- GPP XML containing `cpassword` (decryptable, key is public).
- Startup/logon scripts or Scheduled Task (GPP) items pointing to writable shares.
- Settings weakening security: WDigest enabled, LM hash storage, NTLMv1 allowed (`LmCompatibilityLevel` < 5), SMB signing not required on DCs, LDAP signing/channel binding not enforced, Defender disabled/exclusions, Restricted Groups adding broad groups to local Administrators.
- Audit policy GPO missing or weaker than recommended (`windows-event-log-analysis`).
- Orphaned/unlinked GPOs and SYSVOL folders without GPO objects.

## Detecting malicious GPO changes

5136 (directory object modified) on `groupPolicyContainer` objects, especially `gPCMachineExtensionNames` / `versionNumber` changes; 5137 new GPO; 5141 deleted. File changes in `SYSVOL\...\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml` or `Scripts\` (file integrity monitoring on SYSVOL).

```kusto
SecurityEvent
| where EventID == 5136 and ObjectClass == "groupPolicyContainer"
| project TimeGenerated, SubjectUserName, ObjectDN, AttributeLDAPDisplayName, AttributeValue
```

## Output

`GPO | Linked to | Finding | Setting/ACL | Risk | Recommended change | Owner`

## Related skills

`ad-privileged-access-review`, `ransomware-response`, `endpoint-hardening`

## References

- Microsoft Security Compliance Toolkit: https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10
- MS14-025 (GPP passwords): https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
