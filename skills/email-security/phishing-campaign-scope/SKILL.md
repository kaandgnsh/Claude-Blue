---
name: phishing-campaign-scope
description: Scope a phishing campaign across the mail environment — cluster messages by sender infrastructure, subject, URL domains, attachment hashes and lures; identify all recipients, clickers, and compromised accounts; and purge at scale. Use when multiple users received related phishing or a single report may be part of a larger wave.
license: MIT
metadata:
  category: email-security
  version: "2.0.0"
  verification: documented
---

# Phishing Campaign Scope

## Clustering keys

Sender address/domain, envelope sender, sending IP/ASN (`X-Forefront-Antispam-Report CIP`), subject patterns (with variations), URL domains and paths, attachment SHA-256 and file names, message body hashes/fuzzy hashes, DKIM `d=` domain, reply-to address, QR-decoded URLs.

## Defender for Office 365 / Defender XDR

```kusto
let urls = dynamic(["badlogin-example.test", "files-share-example.test"]);
let mids = EmailUrlInfo | where UrlDomain in (urls) | distinct NetworkMessageId;
EmailEvents
| where Timestamp > ago(14d) and (NetworkMessageId in (mids) or SenderIPv4 == "<ip>" or Subject has "<lure phrase>")
| summarize recipients=dcount(RecipientEmailAddress), delivered=countif(DeliveryAction == "Delivered"),
            first=min(Timestamp), last=max(Timestamp) by SenderFromAddress, Subject
```
Clickers: `UrlClickEvents | where Url has_any (urls)`; post-delivery remediation status: `EmailPostDeliveryEvents`.

Google Workspace: Security investigation tool → Gmail log events (filter by subject/sender/attachment hash), bulk delete; Exchange on-prem: `Get-MessageTrackingLog`.

## Workflow

1. Start from the reported message; extract all clustering keys.
2. Search 14–30 days back for **each** key (attackers rotate senders and subjects but reuse infrastructure).
3. Build the campaign set; record counts: received, delivered, quarantined, clicked, credential submitted (from sign-in correlation), executed (endpoint).
4. Purge all delivered copies; block keys; tune filters.
5. For each interacting user: follow `phishing-triage` severity guide.
6. Report campaign summary and IOCs.

## Output

```
Campaign <name> <first>-<last> UTC
Keys: sender(s), IPs, URL domains, hashes, subjects
Recipients <n> | delivered <n> | clicked <n> | creds submitted <n> | payload executed <n>
Purged <n> at <t> | Blocks applied: <list>
Compromised accounts: <list> → status
```

## Related skills

`phishing-triage`, `email-header-analysis`, `ioc-assessment`, `campaign-correlation`

## References

- Microsoft Defender XDR email tables: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table
- Google Workspace security investigation tool: https://support.google.com/a/answer/7575955
