---
name: m365-audit-investigation
description: Investigate Microsoft 365 activity with the Purview Unified Audit Log (Search-UnifiedAuditLog, Audit search, Graph Audit Log Query API) and Defender XDR CloudAppEvents — Exchange, SharePoint/OneDrive, Teams, Entra operations — for data access, sharing, exfiltration and admin abuse. Use when scoping a Microsoft 365 account or tenant compromise, insider data theft, or data exposure.
license: MIT
metadata:
  category: saas-security
  version: "2.0.0"
  verification: documented
---

# Microsoft 365 Audit Investigation

## Access the Unified Audit Log

```powershell
Connect-ExchangeOnline
$start=(Get-Date).AddDays(-30); $end=Get-Date
Search-UnifiedAuditLog -StartDate $start -EndDate $end -UserIds alice@contoso.com -ResultSize 5000 -SessionCommand ReturnLargeSet |
  Select-Object CreationDate, UserIds, Operations, RecordType, AuditData | Export-Csv alice_ual.csv -NoTypeInformation
# Specific operations tenant-wide
Search-UnifiedAuditLog -StartDate $start -EndDate $end -Operations FileDownloaded,FileSyncDownloadedFull,AnonymousLinkCreated,SharingSet -ResultSize 5000
```
`AuditData` is JSON — expand it (`$_.AuditData | ConvertFrom-Json`) for `ClientIP`, `ObjectId`, `UserAgent`, `SiteUrl`. Large investigations: Purview Audit search jobs or the Microsoft Graph Audit Log Query API; retention depends on licence (Audit Standard vs. Premium). Tools: Microsoft-Extractor-Suite (Invictus IR) automates collection.

## Key operations

| Workload | Operations |
|---|---|
| Exchange | `MailItemsAccessed`, `Send`, `New-InboxRule`/`Set-InboxRule`/`UpdateInboxRules`, `Set-Mailbox` (forwarding), `Add-MailboxPermission`, `SearchQueryInitiated` (Premium) |
| SharePoint/OneDrive | `FileAccessed`, `FileDownloaded`, `FileSyncDownloadedFull`, `FileUploaded`, `AnonymousLinkCreated`, `SharingSet`, `CompanyLinkCreated`, `SearchQueryPerformed` |
| Teams | `MessageSent` (with retention), `MemberAdded`, external access |
| Entra (in UAL) | `Add member to role.`, `Consent to application.`, `Add service principal.` |
| eDiscovery | `New-ComplianceSearch`, `SearchExported` (attackers and insiders use eDiscovery to exfiltrate) |

## Defender XDR alternative

```kusto
CloudAppEvents
| where Timestamp > ago(7d) and AccountDisplayName =~ "Alice Example"
| where ActionType in ("FileDownloaded", "FileSyncDownloadedFull", "AnonymousLinkCreated", "New-InboxRule", "MailItemsAccessed")
| summarize count() by ActionType, IPAddress, bin(Timestamp, 1h)
```

## Analysis tips

- Mass download: count `FileDownloaded` + `FileSyncDownloadedFull` per user/IP/hour vs. baseline.
- Sign-in IP correlation: attacker IPs from `entra-signin-investigation` → filter UAL `ClientIP`.
- Absence of `MailItemsAccessed` may be licensing/throttling, not innocence.

## Related skills

`mailbox-compromise`, `account-compromise-investigation`, `insider-threat-investigation`, `data-exposure-investigation`

## References

- Search the audit log: https://learn.microsoft.com/en-us/purview/audit-search
- Audit log activities: https://learn.microsoft.com/en-us/purview/audit-log-activities
- Microsoft-Extractor-Suite: https://github.com/invictus-ir/Microsoft-Extractor-Suite
- CISA Microsoft Expanded Cloud Logs playbook: https://www.cisa.gov/resources-tools/resources/microsoft-expanded-cloud-logs-implementation-playbook
