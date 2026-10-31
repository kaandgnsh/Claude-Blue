---
name: entra-audit-investigation
description: Investigate Microsoft Entra ID audit logs for persistence and privilege escalation — MFA/authentication method changes, role assignments (incl. PIM), app registrations and credentials, OAuth consent grants, service principal changes, federation/domain changes, Conditional Access edits. Use after suspected account or tenant compromise, or when hunting identity persistence in Entra ID.
license: MIT
metadata:
  category: azure-security
  version: "2.0.0"
  verification: documented
---

# Entra ID Audit Investigation

## High-risk operations (`AuditLogs.OperationName`)

| Area | OperationName examples | Why |
|---|---|---|
| Auth methods | `User registered security info`, `Admin registered security info`, `User changed default security info`, `Update user` (StrongAuthenticationMethod) | Attacker adds own MFA device |
| Roles | `Add member to role`, `Add eligible member to role` (PIM), `Add scoped member to role` | Privilege escalation |
| Apps | `Add application`, `Update application – Certificates and secrets management`, `Add service principal credentials`, `Add owner to application` | Backdoor credentials on apps with high privileges |
| Consent | `Consent to application`, `Add delegated permission grant`, `Add app role assignment to service principal` | OAuth persistence / illicit consent |
| Federation | `Set domain authentication`, `Set federation settings on domain`, `Add unverified domain`, `Verify domain` | Golden SAML / rogue IdP |
| Policy | `Update conditional access policy`, `Delete conditional access policy`, `Update authorization policy` | Defense evasion |
| Users | `Add user`, `Invite external user`, `Reset password (by admin)` | New access paths |

## KQL

```kusto
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Add member to role", "Add eligible member to role", "Consent to application",
    "Add service principal credentials", "Update application – Certificates and secrets management",
    "Set domain authentication", "Set federation settings on domain", "User registered security info",
    "Update conditional access policy", "Delete conditional access policy")
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),
         ActorIP = tostring(InitiatedBy.user.ipAddress),
         Target = tostring(TargetResources[0].displayName), TargetUPN = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, OperationName, Result, Actor, ActorIP, Target, TargetUPN, TargetResources, AdditionalDetails
| order by TimeGenerated asc
```
Note the en dash in "Update application – Certificates and secrets management" — copy exact names from your logs.

Graph PowerShell checks:
```powershell
Connect-MgGraph -Scopes "Directory.Read.All","UserAuthenticationMethod.Read.All"
Get-MgUserAuthenticationMethod -UserId alice@contoso.com | Select-Object Id, AdditionalProperties
Get-MgServicePrincipal -All | Where-Object { $_.PasswordCredentials -or $_.KeyCredentials } | Select DisplayName, AppId
Get-MgDomain | Select Id, AuthenticationType     # Federated domains you don't expect = critical
Get-MgOauth2PermissionGrant -All | Where-Object { $_.ConsentType -eq "AllPrincipals" }
```

## Response

Remove attacker auth methods, role assignments, app credentials and consents; revert federation changes (then rotate token-signing certificates if AD FS/IdP compromised); revoke sessions of affected users; review CA policy changes. Export evidence first.

## Related skills

`entra-signin-investigation`, `oauth-app-review`, `conditional-access-review`, `token-theft-investigation`

## References

- Entra audit log activities: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
- CISA/Microsoft guidance on detecting post-compromise in Entra/M365 (AA21-008A): https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a
- Microsoft app consent grant investigation: https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-app-consent
