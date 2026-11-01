---
name: security-requirements
description: Define verifiable application security requirements using OWASP ASVS 5.0 levels (and MASVS for mobile), mapped to the application's risk, and turn them into acceptance criteria, tests and review checklists. Use when starting a project, writing security acceptance criteria for features, selecting an assurance level, or auditing an application against ASVS.
license: MIT
metadata:
  category: appsec
  version: "2.2.0"
  verification: documented
---

# Security Requirements (ASVS)

## Choose a level

| ASVS level | Use for |
|---|---|
| L1 | Low-risk apps; minimum baseline, largely testable externally |
| L2 | Most apps handling personal or business-sensitive data (default) |
| L3 | High-value apps: critical infrastructure, healthcare, finance, high-assurance identity |

ASVS 5.0 (released 2025) reorganized chapters (e.g., encoding and sanitization, validation and business logic, web frontend security, API and web service, file handling, authentication, session management, authorization, self-contained tokens, OAuth/OIDC, cryptography, secure communication, configuration, data protection, logging and error handling). Requirement IDs changed from 4.0.3 — cite the version.

For all 17 chapters with example acceptance criteria and verification methods, and mappings to the OWASP Top 10:2025, API Security Top 10 2023 and LLM Top 10 2025, read [references/owasp-mappings.md](references/owasp-mappings.md).

## Workflow

1. Classify the app (data, users, exposure) → choose level.
2. Select relevant chapters (skip N/A: e.g., no file upload) and record why.
3. Convert each requirement into **acceptance criteria** for stories, e.g.:
   - "Given a user requests `/orders/{id}` for an order they don't own, the API returns 403/404 and logs an authorization failure." (authorization)
   - "Session cookies have `Secure`, `HttpOnly`, `SameSite=Lax` or `Strict`." (session management)
4. Map each to verification: unit/integration test, SAST rule, DAST check, manual review, pen test.
5. Track coverage per release; exceptions through risk acceptance.

## Output

`ASVS ID (v5.0) | Requirement (short) | Applies? | Acceptance criteria | Verification method | Status | Evidence`

## Related skills

`threat-modeling`, `secure-code-review`, `mobile-app-security-review`, `release-gate`

## References

- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP MASVS: https://mas.owasp.org/MASVS/
- NIST SP 800-218 Secure Software Development Framework (SSDF): https://csrc.nist.gov/pubs/sp/800/218/final
