---
name: ad-privileged-access-review
description: Review Active Directory privileged access — Tier 0 groups, AdminSDHolder/adminCount, krbtgt age, LAPS coverage, delegation, service accounts with SPNs, Protected Users — with PowerShell, PingCastle or Purple Knight. Use for AD security assessments, post-incident AD hardening, or when asked "who is effectively Domain Admin?".
license: MIT
metadata:
  category: active-directory-security
  version: "2.0.0"
  verification: documented
---

# AD Privileged Access Review

## Tier 0 scope

Domain Admins, Enterprise Admins, Schema Admins, Administrators (builtin), Account/Server/Print/Backup Operators, DnsAdmins, Group Policy Creator Owners, Cert Publishers, Key Admins / Enterprise Key Admins, members of any group with control over DCs, ADCS CAs, Entra Connect servers, and accounts with DCSync rights. Machines: DCs, ADCS, AD FS, Entra Connect, PAWs, backup servers with DC access.

## Collection (read-only)

```powershell
Import-Module ActiveDirectory
# Recursive membership of key groups
"Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators","Server Operators","Print Operators","DnsAdmins" |
  ForEach-Object { $g=$_; Get-ADGroupMember $g -Recursive | Select-Object @{n='Group';e={$g}}, SamAccountName, objectClass }
# Accounts protected by AdminSDHolder (current or stale)
Get-ADUser -Filter 'adminCount -eq 1' -Properties adminCount, PasswordLastSet, LastLogonDate, Enabled
# krbtgt password age (reset at least every 180 days is a common guidance)
Get-ADUser krbtgt -Properties PasswordLastSet
# Kerberoastable privileged accounts
Get-ADUser -Filter 'servicePrincipalName -like "*"' -Properties servicePrincipalName, adminCount, PasswordLastSet, msDS-SupportedEncryptionTypes
# Unconstrained delegation (non-DC)
Get-ADComputer -Filter 'TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516' -Properties TrustedForDelegation
# Constrained / RBCD
Get-ADObject -Filter 'msDS-AllowedToDelegateTo -like "*" -or msDS-AllowedToActOnBehalfOfOtherIdentity -like "*"' -Properties msDS-AllowedToDelegateTo
# Password never expires / not required
Get-ADUser -Filter 'PasswordNeverExpires -eq $true -or PasswordNotRequired -eq $true' -Properties PasswordNeverExpires, PasswordNotRequired
# AS-REP roastable
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true'
```
Assessment tools: **PingCastle** (`PingCastle.exe --healthcheck`), **Purple Knight**, **BloodHound** for paths (`ad-attack-path-analysis`).

## Findings to rate

| Finding | Why it matters |
|---|---|
| >5 permanent Domain Admins, or user accounts used daily in DA | Standing privilege; credential exposure on workstations |
| Privileged accounts with SPNs | Kerberoastable → offline cracking |
| krbtgt not reset in >180 days | Golden ticket longevity |
| Unconstrained delegation on non-DCs | TGT capture (printer bug/coercion) |
| Privileged users not in Protected Users / no "sensitive and cannot be delegated" | Delegation, NTLM, RC4 exposure |
| No LAPS (Windows LAPS) on workstations/servers | Shared local admin → lateral movement |
| Stale adminCount=1 accounts | Orphaned privileged ACLs |
| Exchange/Entra Connect/backup service accounts with domain-level rights | Common escalation paths |

## Output template

```
AD privileged access review — <domain> <date>
Tier 0 members: <n> (users <n>, service <n>, stale <n>)
Critical: <finding> — <evidence> — <remediation> — <owner>
Metrics: krbtgt age <d>, LAPS coverage <%>, kerberoastable privileged <n>
```

## Related skills

`ad-attack-path-analysis`, `kerberos-attack-detection`, `privileged-access-review`, `adcs-security-review`

## References

- Microsoft Securing Privileged Access: https://learn.microsoft.com/en-us/security/privileged-access-workstations/overview
- Microsoft Best Practices for Securing AD: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory
- Windows LAPS: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview
- PingCastle: https://www.pingcastle.com/
