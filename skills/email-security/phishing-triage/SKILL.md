---
name: phishing-triage
description: Triage user-reported or detected phishing — classify (credential phish, malware delivery, BEC, callback/TOAD, QR "quishing", spam), analyze safely, determine who received and interacted, and remediate (purge, block, reset). Use when a suspicious email is reported, a mail-security alert fires, or the phish-report mailbox needs working.
license: MIT
metadata:
  category: email-security
  version: "2.0.0"
  verification: documented
---

# Phishing Triage

## Workflow

1. **Get the original** (`.eml`/`.msg`) and parse it (`email-header-analysis`).
2. **Classify**: credential harvesting link, malware attachment/link, BEC/payment request, callback phishing (phone number, fake invoice), QR code, extortion/spam, simulation (check phishing-simulation headers/campaign list before escalating).
3. **Analyze indicators safely**:
   - URLs: expand redirects with a sandbox/URL scanner (urlscan.io private scans, internal detonation), check domain age, hosting, and whether the landing page is an AiTM proxy (Evilginx-style) or a static form.
   - Attachments: hash first; detonate in sandbox; analyze documents with `office-document-analysis`. HTML attachments often contain obfuscated credential forms or HTML smuggling.
   - QR codes: decode offline (`zbarimg image.png`) — do not scan with a phone.
4. **Scope recipients and interaction** (Defender for Office 365 example):
   ```kusto
   EmailEvents | where Timestamp > ago(7d) and (SenderFromAddress =~ "<sender>" or Subject == "<subject>" or NetworkMessageId == "<id>")
   | project Timestamp, RecipientEmailAddress, DeliveryAction, DeliveryLocation, NetworkMessageId
   UrlClickEvents | where Url has "<domain>" | project Timestamp, AccountUpn, ActionType, IsClickedThrough
   ```
   Then check sign-ins for clickers from new IPs (`account-compromise-investigation`) and endpoint activity for attachment openers.
5. **Remediate**: soft/hard delete from mailboxes (Threat Explorer action / `New-ComplianceSearchAction -Purge`), block sender/domain/URL (Tenant Allow/Block List), reset credentials + revoke sessions for users who submitted credentials, isolate hosts that executed payloads.
6. **Respond to reporter** and record the case; feed IOCs to blocking and hunting.

## Severity guide

| Interaction | Severity |
|---|---|
| Delivered, no interaction | Low (purge) |
| Clicked, no credential submission evidence | Medium (verify sign-ins/endpoint) |
| Credentials submitted / MFA approved / token stolen | High (`account-compromise-investigation`) |
| Attachment executed | High (`edr-alert-investigation`) |
| Executive/finance targeted payment fraud | High (`bec-investigation`) |

## Safety

Never click links or open attachments on a workstation; use isolated sandboxes. Use private/unlisted scans for internal-looking URLs (public scanners leak tokens and internal URLs).

## Related skills

`email-header-analysis`, `phishing-campaign-scope`, `office-document-analysis`, `account-compromise-investigation`, `phish-reporting-workflow`

## References

- CISA Phishing guidance: https://www.cisa.gov/resources-tools/resources/phishing-guidance-stopping-attack-cycle-phase-one
- Microsoft Threat Explorer and remediation: https://learn.microsoft.com/en-us/defender-office-365/threat-explorer-real-time-detections-about
- MITRE ATT&CK T1566 Phishing: https://attack.mitre.org/techniques/T1566/
