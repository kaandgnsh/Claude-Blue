---
name: threat-modeling
description: Threat model a system, feature or architecture change — data-flow diagram with trust boundaries, STRIDE (or LINDDUN for privacy, PASTA for risk-centric) threat enumeration, abuse cases, mitigations mapped to owners, and residual risk. Use at design time, before a major release, for security design reviews, or when asked "what could go wrong with this design?".
license: MIT
metadata:
  category: appsec
  version: "2.0.0"
  verification: documented
---

# Threat Modeling

The Threat Modeling Manifesto's four questions: *What are we working on? What can go wrong? What are we going to do about it? Did we do a good enough job?*

## Workflow

1. **Model the system**: DFD with external entities, processes, data stores, data flows; mark **trust boundaries** (internet ↔ edge, service ↔ service, tenant ↔ tenant, user ↔ admin, CI ↔ production). Note data classification on each flow. Tools: OWASP Threat Dragon, draw.io, Microsoft Threat Modeling Tool, threat-model-as-code (pytm, Threagile).
2. **Enumerate threats per element crossing a boundary** using STRIDE:

| STRIDE | Property | Typical questions |
|---|---|---|
| Spoofing | Authentication | Can a caller impersonate a user/service? Token validation, mTLS, webhook signatures |
| Tampering | Integrity | Can data be modified in transit/storage? Input validation, signing, immutable logs |
| Repudiation | Non-repudiation | Are security-relevant actions logged with actor identity? |
| Information disclosure | Confidentiality | Over-broad APIs, error messages, logs with secrets, IDOR, cross-tenant leakage |
| Denial of service | Availability | Unbounded queries, expensive operations, rate limits, queue floods |
| Elevation of privilege | Authorization | Missing object-level checks, role escalation, SSRF to metadata, deserialization |

3. **Add abuse cases** specific to the business (fraud, scraping, account takeover, prompt injection for LLM features — see `prompt-injection-review`).
4. **Rate** (likelihood × impact or simple High/Med/Low) and **decide**: mitigate, transfer, accept, eliminate.
5. **Track mitigations** as tickets/requirements with owners; link to ASVS requirements (`security-requirements`).
6. **Validate**: tests (unit/integration security tests, DAST, pen test) proving mitigations; revisit model on architecture change.

## Output template

```
Threat model <system/feature> v<> <date>  Participants: <>
Scope & assumptions: <>
DFD: <link>   Trust boundaries: <list>
# | Element/flow | STRIDE | Threat | Existing control | Risk | Mitigation | Owner | Ticket | Status
Accepted risks: <with approver>
```

## Related skills

`secure-code-review`, `security-requirements`, `trust-boundary-analysis`, `architecture-review`, `pipeline-threat-model`

## References

- Threat Modeling Manifesto: https://www.threatmodelingmanifesto.org/
- OWASP Threat Modeling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
- OWASP Threat Dragon: https://owasp.org/www-project-threat-dragon/
- LINDDUN privacy threat modeling: https://linddun.org/
