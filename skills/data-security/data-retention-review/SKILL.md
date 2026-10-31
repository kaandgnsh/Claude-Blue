---
name: data-retention-review
description: Review data retention and disposal — retention schedules by record type and legal requirement, retention labels/policies (Purview, Google Vault), backup and log retention, legal holds, and verifiable deletion — to reduce breach impact and meet storage-limitation obligations. Use when defining retention, auditing over-retention, preparing for legal holds, or reducing data held after a breach.
license: MIT
metadata:
  category: data-security
  version: "2.0.0"
  verification: documented
---

# Data Retention Review

## Build the schedule

`Record type | System(s) | Owner | Legal/regulatory basis | Minimum retention | Maximum retention | Disposal method | Legal-hold capable`

Examples of drivers (verify with counsel for each jurisdiction): tax/accounting records (often 6–10 years), employment records, PCI DSS (minimize cardholder data; audit logs 12 months), healthcare records, GDPR storage limitation (no longer than necessary), security logs (≥ 1 year common), CCTV (short, e.g. 30 days).

## Assess current state

1. For each major store: actual oldest data vs. schedule (query min creation date, object age distribution).
2. Check that retention policies are **configured** (Purview retention policies/labels, Google Vault retention rules, S3 lifecycle, database purge jobs) and **working** (sampling records past max retention).
3. Backups: retention per tier, and whether deletion in production propagates (it usually doesn't — document backup expiry as the effective deletion date).
4. Logs: security logs kept long enough for investigations, but PII in logs minimized (`telemetry-minimization`).
5. Legal holds: process to suspend deletion; holds released when matters close.

## Disposal

Use provider deletion with verification (lifecycle expiration, crypto-shredding by destroying keys for encrypted stores, NIST SP 800-88 media sanitization for hardware). Record disposal evidence for audits.

## Findings to flag

Data far older than any requirement ("keep forever" defaults), production copies in dev/test, abandoned buckets/shares, mailboxes of leavers retained indefinitely, retention policy in "simulation" mode only.

## Related skills

`data-discovery`, `data-classification`, `telemetry-minimization`, `backup-assurance`

## References

- Microsoft Purview data lifecycle management: https://learn.microsoft.com/en-us/purview/data-lifecycle-management
- NIST SP 800-88 Rev. 2 Guidelines for Media Sanitization: https://csrc.nist.gov/pubs/sp/800/88/r2/final
- GDPR Art. 5(1)(e) storage limitation: https://gdpr-info.eu/art-5-gdpr/
