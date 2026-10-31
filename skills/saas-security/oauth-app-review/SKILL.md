---
name: oauth-app-review
description: Review and investigate OAuth applications and consents in Microsoft Entra ID, Google Workspace, GitHub, Slack and Salesforce — high-risk scopes, multi-tenant apps, unverified publishers, user vs. admin consent, illicit consent grants, app credentials — and revoke malicious apps. Use when auditing third-party app access, investigating consent phishing, or locking down app consent policy.
license: MIT
metadata:
  category: saas-security
  version: "2.0.0"
  verification: documented
---

# OAuth Application Review

## High-risk permissions

| Platform | Scopes/permissions |
|---|---|
| Microsoft Graph | `Mail.Read`, `Mail.ReadWrite`, `Mail.Send`, `Files.Read.All`, `Files.ReadWrite.All`, `Sites.Read.All`, `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `offline_access` (long-lived refresh), `full_access_as_app` (EWS) |
| Google | `https://mail.google.com/`, `gmail.readonly`, `drive`, `drive.readonly`, `admin.directory.*`, `cloud-platform` |
| GitHub | `repo`, `admin:org`, `workflow`, `write:packages`; GitHub Apps with `contents: write`, `administration` |
| Slack | `channels:history`, `files:read`, `admin.*` |

## Inventory

Entra:
```powershell
Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All"
Get-MgOauth2PermissionGrant -All | Select-Object ClientId, ConsentType, PrincipalId, Scope       # delegated
Get-MgServicePrincipal -All | ForEach-Object { $sp=$_; Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id |
  Select-Object @{n='App';e={$sp.DisplayName}}, ResourceDisplayName, AppRoleId }                   # application permissions
```
Defender for Cloud Apps App governance (if licensed) scores apps; Google: `gam all users print tokens`; GitHub: org Settings → Third-party access / installed GitHub Apps (`gh api orgs/ORG/installations`).

## Red flags

- Recently created multi-tenant app with an unverified publisher requesting mail/files scopes.
- Display name imitating Microsoft/Google/known brands; reply URLs on suspicious domains.
- Consent granted by one user right after clicking a phishing link (`AuditLogs` "Consent to application").
- App with application permissions (no user context) to mail/files across tenant.
- New credentials added to an existing high-privilege app (`Add service principal credentials`).

## Remediate

Revoke consents (`Remove-MgOauth2PermissionGrant`), disable/delete service principal, block app ID (Google: block in API controls; GitHub: revoke OAuth app/installation), review what the app accessed (MailItemsAccessed with AppId, `CloudAppEvents`), and restrict user consent: Entra "Allow user consent for apps from verified publishers, for selected permissions" + admin consent workflow.

## Related skills

`entra-audit-investigation`, `google-workspace-audit`, `mailbox-compromise`, `third-party-access-review`

## References

- Microsoft app consent grant investigation: https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-app-consent
- Configure user consent: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent
- MITRE ATT&CK T1528 Steal Application Access Token: https://attack.mitre.org/techniques/T1528/
- Google Workspace API access control: https://support.google.com/a/answer/7281227
