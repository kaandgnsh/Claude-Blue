---
name: orphan-account-review
description: Find and remediate orphaned, dormant, shared and unowned accounts across AD, Entra ID, cloud IAM, databases and SaaS — accounts without an active owner, stale logins, generic/shared names, local admin accounts — with owner attribution and safe disable-then-delete workflow. Use for identity hygiene projects, audit findings on stale accounts, or attack-surface reduction.
license: MIT
metadata:
  category: identity-governance
  version: "2.0.0"
  verification: documented
---

# Orphan and Dormant Account Review

## Find candidates

AD:
```powershell
$cutoff = (Get-Date).AddDays(-90)
Get-ADUser -Filter 'Enabled -eq $true' -Properties LastLogonTimestamp, PasswordLastSet, Manager, Description, whenCreated |
  Where-Object { $_.LastLogonTimestamp -and [datetime]::FromFileTime($_.LastLogonTimestamp) -lt $cutoff } |
  Select-Object SamAccountName, @{n='LastLogon';e={[datetime]::FromFileTime($_.LastLogonTimestamp)}}, PasswordLastSet, Manager, Description
Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly | Where-Object Enabled
```
(`LastLogonTimestamp` replicates with up to ~14 days lag — fine for 90-day dormancy.)

Entra ID: `signInActivity` (needs AuditLog.Read.All):
```powershell
Get-MgUser -All -Property DisplayName,UserPrincipalName,AccountEnabled,SignInActivity,UserType |
  Where-Object { $_.AccountEnabled -and $_.SignInActivity.LastSignInDateTime -lt (Get-Date).AddDays(-90) }
```
AWS credential report (`password_last_used`, `access_key_*_last_used_date`), GCP IAM recommender / Activity Analyzer, database `pg_stat_activity`/login audit, SaaS admin exports.

## Classify

| Class | Example | Action |
|---|---|---|
| Orphan | Owner terminated (no HR match) | Disable; find new owner or delete |
| Dormant | Valid owner, no use 90+ days | Disable after owner confirmation |
| Shared/generic | `admin`, `test`, `scanner`, `training01` | Replace with named or managed identities; vault if unavoidable |
| Service w/o owner | SPN account, app credential | Assign owner (`service-account-review`) |
| Never logged in | Created > 30 days, never used | Disable |

## Safe remediation

Disable → move to quarantine OU / tag with date → wait 30 days (monitor for breakage tickets) → delete. Keep evidence for audit. Never delete service accounts without dependency checks (logon events on servers, scheduled tasks, services, app configs).

## Related skills

`joiner-mover-leaver`, `service-account-review`, `access-certification`

## References

- CIS Controls v8.1 Control 5 (Account Management): https://www.cisecurity.org/controls/account-management
- Microsoft Entra: How to manage inactive user accounts: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts
