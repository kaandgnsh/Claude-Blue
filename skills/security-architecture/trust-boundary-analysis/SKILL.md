---
name: trust-boundary-analysis
description: Identify and analyze trust boundaries in a system — where data or control crosses between principals or privilege levels (internet/edge, tenant/tenant, user/admin, service/service, CI/production, LLM/tools) — and verify authentication, authorization, validation and logging at each crossing. Use when running design reviews or threat models, or when assessing blast radius of a component compromise.
license: MIT
metadata:
  category: security-architecture
  version: "2.0.0"
  verification: documented
---

# Trust Boundary Analysis

## Common boundaries

| Boundary | What must hold at the crossing |
|---|---|
| Internet → edge (LB/WAF/API gateway) | TLS, authentication, rate limiting, input validation, DDoS protection |
| Edge → internal services | Service authentication (mTLS/JWT audience), no trust in client-supplied headers (`X-Forwarded-For`, `X-User-Id`) unless set by the edge and stripped from clients |
| Tenant A ↔ tenant B (multi-tenant SaaS) | Tenant ID from authenticated context, enforced in every query (row-level security), separate keys where needed |
| User → admin functions | Separate authn strength, authorization checks, audit |
| Service → data store | Least-privilege credentials per service, network restrictions |
| Workload → cloud control plane | Scoped workload identity, metadata service protection (IMDSv2, no SSRF) |
| CI → production | Deploy credentials only in protected environments; provenance verification |
| Third-party integration / webhook → system | Signature verification, replay protection, schema validation |
| LLM / agent → tools and data | Treat model output as untrusted input; authorization by the end user's identity (`agent-tool-permission-review`) |
| Admin workstation → Tier 0 | PAW, MFA, JIT |

## Method

1. Draw components with privilege level and owner; draw every data/control flow.
2. Mark each flow where the sender is less trusted than the receiver (or different tenant/principal).
3. For each crossing, record: authentication, authorization, validation, rate limiting, logging. Missing items = findings.
4. **Blast radius**: for each component, ask "if this is fully compromised, what can it reach and with which credentials?" — reduce via segmentation and credential scoping.

## Output

`Boundary | Flow | From (trust) | To (trust) | AuthN | AuthZ | Validation | Logging | Gap | Fix`

## Related skills

`threat-modeling`, `architecture-review`, `api-authorization-testing`, `agent-tool-permission-review`

## References

- OWASP Threat Modeling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
- Microsoft Threat Modeling Tool trust boundaries: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-feature-overview
