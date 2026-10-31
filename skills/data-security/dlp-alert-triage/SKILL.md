---
name: dlp-alert-triage
description: Triage data loss prevention alerts (Microsoft Purview DLP, Google Workspace DLP, Netskope/Zscaler/Forcepoint, endpoint DLP) — validate the matched content, channel and destination, distinguish business process from exfiltration or mistake, and respond proportionately with privacy-aware handling. Use when DLP alerts need review, a DLP policy is too noisy, or a DLP event may be an insider or breach indicator.
license: MIT
metadata:
  category: data-security
  version: "2.0.0"
  verification: documented
---

# DLP Alert Triage

## Questions per alert

1. **What matched?** Sensitive information type (SIT) and confidence, match count, exact data match / fingerprint / trainable classifier, sensitivity label. Validate a sample: many "credit card" hits are random 16-digit numbers that pass Luhn; national ID patterns collide with order numbers.
2. **Channel & destination**: email to external domain, personal webmail upload, USB copy, cloud storage sync, print, Teams/Slack external chat, GenAI site paste, browser upload to unsanctioned SaaS.
3. **Volume**: one document vs. bulk (hundreds of files, archive files, large attachments).
4. **Context**: user role and normal workflow (HR sending payroll to the payroll provider is expected), recipient relationship, timing (resignation notice, off-hours, after a PIP — `insider-threat-investigation`), policy override justification text.
5. **Outcome**: blocked, allowed with justification, audit-only.

## Microsoft Purview evidence

Activity explorer (filter by DLP rule, user, activity), DLP alerts in Defender XDR, `CloudAppEvents`/`DeviceEvents` (`ActionType` like `DlpPolicyMatch`/endpoint DLP actions). Unified audit `DLPRuleMatch` records.

## Disposition

| Case | Action |
|---|---|
| False positive (pattern mismatch) | Tune SIT confidence/proximity, add exclusions for known document templates |
| Business process | Document; create policy exception for the sanctioned channel (e.g., secure transfer to provider) |
| User mistake (wrong recipient) | Recall/delete if possible, notify recipient to delete, coach user; assess notification duty (`privacy-incident-assessment`) |
| Suspicious/malicious | Preserve evidence, escalate to insider-risk/IR with HR/legal involvement; avoid tipping off |

## Privacy

DLP review exposes sensitive content to analysts — restrict roles, view minimal content, log reviewer access, follow works-council/employee-monitoring rules in the jurisdiction.

## Related skills

`insider-threat-investigation`, `data-classification`, `privacy-incident-assessment`, `alert-tuning`

## References

- Microsoft Purview DLP: https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp
- Purview DLP alerts investigation: https://learn.microsoft.com/en-us/purview/dlp-alerts-dashboard-learn
- NIST SP 1800-28 Data Confidentiality: Identifying and Protecting Assets Against Data Breaches: https://www.nccoe.nist.gov/data-confidentiality-identifying-and-protecting-assets-against-data-breaches
