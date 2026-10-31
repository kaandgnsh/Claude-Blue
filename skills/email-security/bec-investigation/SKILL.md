---
name: bec-investigation
description: Investigate business email compromise and payment fraud — vendor/executive impersonation, look-alike domains, compromised vendor mailboxes, invoice/bank-detail change requests — and drive fund recovery, notification and controls. Use when a payment was diverted or requested fraudulently, or a mailbox is used to manipulate finance processes.
license: MIT
metadata:
  category: email-security
  version: "2.0.0"
  verification: documented
---

# BEC Investigation

## First hour if money moved

1. **Contact the bank immediately** to request a recall/hold (SWIFT recall, ACH reversal); time is critical.
2. File with law enforcement (US: FBI IC3 — the Recovery Asset Team works with banks on recent domestic transfers; other countries: national cybercrime unit).
3. Preserve emails (full headers), invoices, payment records, call logs.
4. Engage legal, finance leadership, insurer.

## Determine the BEC variant

| Variant | Evidence to seek |
|---|---|
| Internal mailbox compromised | Sign-ins from attacker IPs, inbox rules, sent items, `MailItemsAccessed` (`mailbox-compromise`) |
| Vendor mailbox compromised | Emails pass DMARC for the vendor's real domain but bank details changed; inform the vendor |
| Look-alike domain | Domain differs subtly (e.g. `examp1e.com`), recently registered; DMARC "passes" for the attacker's domain |
| Display-name spoofing | Free-mail address with executive's display name |
| Thread hijack | Attacker inserted into a real conversation (often after compromise of either party) |

## Analysis

- Reconstruct the conversation: who introduced the change in bank details, from which address/domain, when; compare to genuine earlier messages (headers, signatures, Message-ID domains, sending IPs).
- Check whether the attacker had visibility (rules hiding replies, forwarding) — determines which mailbox was compromised.
- Search for other finance threads touched by the same infrastructure (`phishing-campaign-scope`).
- Look-alike domains: RDAP registration date, MX, hosting; request takedown via registrar abuse contact.

## Controls to recommend

Out-of-band verification of bank-detail changes (call-back to a number on file), dual approval for payments, external-sender tagging, look-alike domain monitoring, DMARC `p=reject` on own domains, MFA phishing-resistant for finance users, mailbox audit + alerting on inbox rules.

## Related skills

`mailbox-compromise`, `email-header-analysis`, `account-compromise-investigation`, `vendor-incident-response`

## References

- FBI IC3 BEC: https://www.ic3.gov/
- FBI BEC public service announcements: https://www.ic3.gov/PSA
- Microsoft: Business email compromise: https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing
