---
name: departing-employee-review
description: Review data-exfiltration risk around employee and contractor departures — look-back over the notice period for bulk downloads, personal-account sharing, USB copies, source code clones and forwarding; coordinate timely deprovisioning and device return. Use when someone resigns or is terminated (especially from sensitive roles), or as a standard offboarding control.
license: MIT
metadata:
  category: insider-risk
  version: "2.0.0"
  verification: documented
---

# Departing Employee Review

## Trigger and scope

HR notice of departure → risk tiering (role access to IP, customer data, finance, source code; involuntary termination; moving to competitor). High-risk departures get a full review; others get automated checks. Agree the policy with HR/legal and disclose monitoring in employee notices.

## Look-back window

Typically 30–90 days before notice through last day (data theft often happens before resignation).

## Checks

| Area | Example query / source |
|---|---|
| Cloud files | M365 UAL `FileDownloaded`/`FileSyncDownloadedFull` count vs. user baseline; `SharingSet`/`AnonymousLinkCreated` to external/personal addresses |
| Email | `Send` with attachments to personal domains (gmail.com, outlook.com…); auto-forwarding rules |
| Endpoint | USB writes (Defender `DeviceEvents` `UsbDriveMounted`/removable storage file events), archive tools, cloud sync clients for personal accounts |
| Code | Git clone/download volume, forks to personal accounts |
| SaaS | CRM report exports, contact list exports |
| Printing | Large print jobs |

Defender XDR example:
```kusto
CloudAppEvents
| where Timestamp > ago(60d) and AccountObjectId == "<user object id>"
| where ActionType in ("FileDownloaded", "FileSyncDownloadedFull", "AnonymousLinkCreated", "SharingSet")
| summarize count() by ActionType, bin(Timestamp, 1d)
```

## Offboarding controls

Disable access at departure time (immediately for involuntary), revoke sessions/tokens, remove personal devices' managed app data (selective wipe), recover corporate devices, transfer ownership of files/mailboxes, rotate shared secrets the person knew, review delegated access they granted.

## Escalation

Significant anomalies → `insider-threat-investigation` with HR/legal; keep findings confidential.

## Related skills

`insider-threat-investigation`, `joiner-mover-leaver`, `m365-audit-investigation`, `dlp-alert-triage`

## References

- CISA Insider Threat Mitigation Guide: https://www.cisa.gov/resources-tools/resources/insider-threat-mitigation-guide
- Microsoft Purview Insider Risk Management (data theft by departing users policy): https://learn.microsoft.com/en-us/purview/insider-risk-management-policy-templates
