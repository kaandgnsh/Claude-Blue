---
name: service-account-review
description: Inventory and secure non-human identities — AD service accounts, gMSA/dMSA, Entra service principals and managed identities, cloud IAM roles and keys, API tokens, CI/CD credentials — for ownership, privilege, credential age, interactive-logon misuse and anomalous behaviour. Use for NHI governance reviews, before decommissioning systems, or when a service credential may be abused.
license: MIT
metadata:
  category: identity-security
  version: "2.0.0"
  verification: documented
---

# Service Account / Non-Human Identity Review

## Inventory sources

| Platform | Command / source |
|---|---|
| AD | `Get-ADUser -Filter 'servicePrincipalName -like "*"' -Properties servicePrincipalName,PasswordLastSet,LastLogonDate,adminCount`; `Get-ADServiceAccount -Filter *` (gMSA) ; accounts in "Service Accounts" OUs |
| Entra | `Get-MgServicePrincipal -All` (with `PasswordCredentials`, `KeyCredentials`, app role assignments); managed identities; Workload ID premium insights |
| AWS | IAM users with access keys and no console (`credential report`), roles assumed by services |
| GCP | `gcloud iam service-accounts list`, keys (`gcp-service-account-keys`) |
| SaaS / CI | GitHub Apps/PATs, CI secrets, API tokens in Okta/Salesforce/Slack |

## Review criteria

- **Owner** named (team + person), purpose, system.
- **Credential**: rotation age (passwords > 1 year, keys > 90 days = finding); prefer gMSA/dMSA, managed identities, workload identity federation over static secrets.
- **Privilege**: least privilege; service accounts in Domain Admins/Global Admin are critical findings.
- **Logon restrictions**: AD — "Deny log on locally / through RDP" for service accounts, `userWorkstations` restriction; cloud — conditions on source (VPC, IP) where possible.
- **Activity**: unused for 90 days → disable then delete; interactive logons (4624 type 2/10) by a service account → investigate.
- **Kerberoastability**: SPN + weak/old password → rotate to 30+ random chars or convert to gMSA (`kerberos-attack-detection`).

## Anomaly detection ideas

Service account used from a new host/IP, interactive logon, new API scope usage, sign-ins outside the workload's region, credential added to an app registration (`entra-audit-investigation`).

## Output

`Identity | Platform | Owner | Purpose | Privilege | Credential type/age | Last used | Findings | Action`

## Related skills

`privileged-access-review`, `orphan-account-review`, `gcp-service-account-keys`, `kerberos-attack-detection`

## References

- Microsoft: Securing service accounts: https://learn.microsoft.com/en-us/entra/architecture/service-accounts-on-premises
- Group Managed Service Accounts: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview
- OWASP Non-Human Identities Top 10: https://owasp.org/www-project-non-human-identities-top-10/
