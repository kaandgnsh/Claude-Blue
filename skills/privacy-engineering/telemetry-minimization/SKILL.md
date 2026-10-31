---
name: telemetry-minimization
description: Minimize personal data in security and application telemetry without losing detection value — field-level review of logs, pseudonymization/hashing with keyed HMAC, IP truncation, payload redaction, separate retention tiers and access controls for sensitive log fields. Use when designing logging pipelines, answering privacy concerns about SIEM/EDR data, or removing secrets and PII from logs.
license: MIT
metadata:
  category: privacy-engineering
  version: "2.0.0"
  verification: documented
---

# Telemetry Minimization

Security monitoring has legitimate interest, but logs often contain more personal data than detections need — and logs leak (T1005, compromised SIEM accounts, vendor access).

## Field review

For each log source list fields and classify:

| Class | Example fields | Treatment |
|---|---|---|
| Needed for detection & investigation | user ID, source IP, host, process, action, outcome | Keep; restrict access by role |
| Needed only for rare investigations | full URL query strings, email subjects, file names in personal folders | Keep in restricted/shorter-retention tier, or hash |
| Not needed | message bodies, form data, cookies, auth headers, passwords/secrets, health/biometric data | Drop or redact at source/pipeline |

## Techniques

- **Redaction** in pipeline (Cribl, Vector, Logstash, Fluent Bit): remove `Authorization`, `Cookie`, `Set-Cookie`, `password=`, tokens (JWT pattern), card numbers (Luhn-valid 13–19 digits).
- **Keyed pseudonymization**: `HMAC-SHA256(key, user_id)` — stable for correlation, reversible only via a lookup held by a restricted team; plain unsalted hashing of emails/IPs is trivially reversible by enumeration.
- **IP truncation** (/24 IPv4, /48 IPv6) for analytics data that doesn't need exact IPs — not for security detection logs where exact IPs matter.
- **Aggregation** for metrics.
- **Tiered retention**: detailed logs 90 days hot, minimized/aggregated longer.

Vector example (VRL) to drop a header and mask an email:
```
.http.request.headers = del(.http.request.headers.authorization)
.user.email = replace(string!(.user.email), r'^[^@]+', "***")
```

## Governance

Document purposes, legal basis (often legitimate interest; works-council agreements in some countries), access roles, retention per tier, and log-access auditing for analysts.

## Related skills

`privacy-preserving-ir`, `data-retention-review`, `log-source-onboarding`, `dpia`

## References

- OWASP Logging Cheat Sheet (data to exclude): https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- ENISA Pseudonymisation techniques and best practices: https://www.enisa.europa.eu/publications/pseudonymisation-techniques-and-best-practices
- Vector Remap Language: https://vector.dev/docs/reference/vrl/
