---
name: mailbox-compromise
description: Investigate a compromised Microsoft 365 or Google Workspace mailbox — malicious inbox rules, forwarding, delegate/OAuth access, MailItemsAccessed and Send activity, sign-in source — and remediate. Use when a user's account sent phishing, inbox rules hide messages, or BEC/account takeover of email is suspected.
license: MIT
metadata:
  category: email-security
  version: "2.0.0"
  verification: documented
---

# Mailbox Compromise Investigation

## Microsoft 365 checks

```powershell
Connect-ExchangeOnline
Get-InboxRule -Mailbox alice@contoso.com | Select-Object Name, Enabled, From, SubjectContainsWords, MoveToFolder, DeleteMessage, ForwardTo, RedirectTo, MarkAsRead
Get-Mailbox alice@contoso.com | Select-Object ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward
Get-MailboxPermission alice@contoso.com | Where-Object { $_.User -notlike "NT AUTHORITY*" }
Get-RecipientPermission alice@contoso.com
Get-MailboxFolderPermission -Identity "alice@contoso.com:\Inbox"
```
Unified Audit Log (Purview, or `Search-UnifiedAuditLog`):
```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -UserIds alice@contoso.com `
  -Operations New-InboxRule,Set-InboxRule,UpdateInboxRules,Set-Mailbox,Add-MailboxPermission,MailItemsAccessed,Send,SoftDelete,HardDelete -ResultSize 5000
```
`MailItemsAccessed` (bind/sync, needs appropriate audit licensing) shows which messages an attacker read — critical for breach scoping.

## Attacker patterns

- Inbox rules with names like `.`, `..`, `xx`, moving messages containing "invoice", "payment", "wire", "hacked", the CFO's name, to RSS Feeds / Conversation History / Archive, marking as read.
- External forwarding (`ForwardingSmtpAddress`, transport rules created by compromised admins).
- OAuth app consent with `Mail.Read`/`Mail.Send` (`oauth-app-review`).
- Sign-ins from hosting provider IPs, unfamiliar user agents (`python-requests`, `axios`), AiTM proxies (sign-in from attacker IP right after phish click).
- New MFA method registered; legacy protocols (IMAP/POP/SMTP AUTH) access.

## Google Workspace

Admin console → Reporting → Audit and investigation → **Gmail log events** (filters, forwarding, delegation), **User log events** (logins), **OAuth log events**. Check user settings for filters/forwarding/delegates via Admin SDK or GAM (`gam user alice show filters`, `show forwards`, `show delegates`).

## Remediation (coordinate with containment plan)

Revoke sessions & reset password (and MFA methods if tampered), remove rules/forwarding/delegates/app consents, block attacker IPs, purge phishing sent from the account, notify recipients, review what data was accessed (MailItemsAccessed, SharePoint/OneDrive `FileAccessed`).

## Related skills

`bec-investigation`, `account-compromise-investigation`, `m365-audit-investigation`, `oauth-app-review`

## References

- Microsoft: Responding to a compromised email account: https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account
- MailItemsAccessed: https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts
- CISA/Microsoft guidance on M365 logging (Expanded Cloud Logs): https://www.cisa.gov/resources-tools/resources/microsoft-expanded-cloud-logs-implementation-playbook
