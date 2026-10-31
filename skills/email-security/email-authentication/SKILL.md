---
name: email-authentication
description: Assess and deploy SPF, DKIM, DMARC (and BIMI, MTA-STS, TLS-RPT) for a domain — record syntax, 10-DNS-lookup limit, alignment, DMARC aggregate report analysis and safe policy progression to p=reject. Use when checking a domain's anti-spoofing posture, troubleshooting legitimate mail failing DMARC, or meeting bulk-sender requirements.
license: MIT
metadata:
  category: email-security
  version: "2.0.0"
  verification: documented
---

# Email Authentication (SPF / DKIM / DMARC)

## Lookups

```sh
dig +short TXT example.com | grep -i 'v=spf1'
dig +short TXT _dmarc.example.com
dig +short TXT selector1._domainkey.example.com     # selector from DKIM-Signature s= tag
dig +short TXT _mta-sts.example.com ; curl -s https://mta-sts.example.com/.well-known/mta-sts.txt
dig +short TXT _smtp._tls.example.com               # TLS-RPT
```

## SPF

`v=spf1 include:_spf.google.com include:spf.protection.outlook.com ip4:198.51.100.0/24 -all`
- Max **10 DNS-querying mechanisms** (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`) including nested — exceeding gives `permerror`. Count recursively.
- End with `-all` (fail) or `~all` (softfail); never `+all`. Only one SPF record per name.
- Parked/non-sending domains: `v=spf1 -all`.

## DKIM

2048-bit keys, rotate selectors periodically, sign with the From domain (or a subdomain for relaxed alignment). Each third-party sender (ESP, CRM, ticketing) needs its own selector and signing.

## DMARC

`v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc-rua@example.com; adkim=r; aspf=r; pct=100`
- Passes if SPF **or** DKIM passes **and aligns** with the From domain.
- Progression: `p=none` with `rua` → identify all legitimate sources from aggregate reports → fix SPF/DKIM for each → `p=quarantine` (optionally `pct`) → `p=reject`.
- Non-sending domains and subdomains: `p=reject` immediately.
- Bulk sender rules (Google/Yahoo 2024, Microsoft 2025 for high volume) require SPF+DKIM+DMARC (at least `p=none`) and one-click unsubscribe for marketing mail.

## Aggregate report analysis

RUA reports are XML (`feedback/record/row/source_ip`, `policy_evaluated/dkim|spf`, `identifiers/header_from`). Parse with a DMARC analyzer (parsedmarc, commercial services) and classify sources: authorized-aligned, authorized-misaligned (fix), unauthorized (spoofing).

## Output

`Domain | SPF (valid, lookups n/10, qualifier) | DKIM selectors | DMARC policy/sp/rua | MTA-STS | Findings | Next step`

## Related skills

`email-header-analysis`, `phishing-triage`, `external-attack-surface-review`

## References

- RFC 7208 SPF: https://www.rfc-editor.org/rfc/rfc7208
- RFC 6376 DKIM: https://www.rfc-editor.org/rfc/rfc6376
- RFC 7489 DMARC: https://www.rfc-editor.org/rfc/rfc7489
- RFC 8461 MTA-STS: https://www.rfc-editor.org/rfc/rfc8461
- Google email sender guidelines: https://support.google.com/a/answer/81126
- parsedmarc: https://github.com/domainaware/parsedmarc
