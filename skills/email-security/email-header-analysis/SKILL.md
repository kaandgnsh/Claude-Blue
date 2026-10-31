---
name: email-header-analysis
description: Analyze email headers and message structure — Received chain, Return-Path/From/Reply-To alignment, Authentication-Results (SPF, DKIM, DMARC, ARC), Message-ID, X-headers, URLs and attachments — with a bundled tested .eml parser. Use when determining whether an email is spoofed, where it really came from, or extracting indicators from a reported message.
license: MIT
metadata:
  category: email-security
  version: "2.0.0"
  verification: tested
---

# Email Header Analysis

## Bundled parser (safe: does not open links or attachments)

```sh
python3 scripts/parse_eml.py reported.eml > reported.json
```
Outputs sender addresses, Return-Path, Reply-To, parsed `Authentication-Results`, Received hops (oldest first, with IPs and times), defanged URLs, attachment names/types/SHA-256, and flags such as `reply-to domain differs from From domain` or `dmarc=fail`.

Obtain the original message with full headers (Outlook: *View → Message source* / "Download message"; M365 Explorer/Threat Explorer download; Gmail *Show original*). Forwarded copies lose original headers — ask for the message as attachment.

## Reading headers

| Header | What it tells you |
|---|---|
| `Received` | Each relay prepends one; read **bottom-up**. Only hops added by *your* infrastructure are trustworthy; earlier ones can be forged |
| `Authentication-Results` (added by your gateway) | `spf=` (envelope sender's domain authorized this IP?), `dkim=` (signature valid, `header.d=` signing domain), `dmarc=` (aligned with From domain?), `compauth=` (Microsoft composite) |
| `Return-Path` / envelope from | Bounce address (SPF domain) — often differs legitimately for ESPs |
| `From` | What users see; DMARC protects this domain only if published at `p=quarantine/reject` |
| `Reply-To` | BEC tell when it points to a different (free-mail/look-alike) domain |
| `Message-ID` | Domain often reveals sending platform |
| `X-MS-Exchange-Organization-SCL`, `X-Forefront-Antispam-Report` | Microsoft filtering verdicts (SCL, SFV, CIP = connecting IP) |
| `ARC-*` | Authentication chain through forwarders/mailing lists |

## Verdict logic

- DMARC pass + known sender + no anomalies → likely legitimate (still check content/links — compromised legitimate accounts send DMARC-passing phish).
- DMARC fail on a domain with `p=none` → spoofing possible; check SPF/DKIM individually.
- Display-name impersonation (`"CEO Name" <random@gmail.com>`) — authentication passes for gmail.com; the attack is social.
- Look-alike domains (`rn` vs `m`, extra hyphen, different TLD): compare character by character; check registration date.

## Related skills

`phishing-triage`, `email-authentication`, `bec-investigation`, `ioc-assessment`

## References

- RFC 5322 (Internet Message Format): https://www.rfc-editor.org/rfc/rfc5322
- RFC 8601 (Authentication-Results): https://www.rfc-editor.org/rfc/rfc8601
- RFC 7489 (DMARC): https://www.rfc-editor.org/rfc/rfc7489
- Microsoft anti-spam message headers: https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo
