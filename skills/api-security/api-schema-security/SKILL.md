---
name: api-schema-security
description: Review and lint API specifications (OpenAPI 3.x, GraphQL schemas) for security — authentication on every operation, strict schemas (additionalProperties false, formats, max lengths), rate-limit and pagination limits, sensitive fields, server URLs — with Spectral/OWASP rulesets, and enforce schema validation at the gateway. Use when reviewing an API design, adding API linting to CI, or hardening request validation.
license: MIT
metadata:
  category: api-security
  version: "2.0.0"
  verification: documented
---

# API Schema Security

## Lint

```sh
npx @stoplight/spectral-cli lint openapi.yaml --ruleset .spectral.yaml
```
`.spectral.yaml`:
```yaml
extends:
  - spectral:oas
  - https://unpkg.com/@stoplight/spectral-owasp-ruleset/dist/ruleset.mjs
```
The OWASP ruleset flags missing security schemes, HTTP servers, unbounded strings/arrays, missing rate-limit headers, numeric IDs, and more. 42Crunch and similar tools provide commercial audits.

## Checklist

| Area | Check |
|---|---|
| AuthN | Global `security` requirement; no operation with `security: []` unless intentionally public |
| Schemas | `additionalProperties: false` on request bodies (prevents mass assignment), `maxLength`/`pattern`/`format` on strings, `maxItems` on arrays, numeric `minimum/maximum` |
| Identifiers | Prefer non-sequential IDs; never rely on them for authorization |
| Responses | Explicit response schemas; no internal fields (hashes, internal IDs, tokens) |
| Pagination | Enforced max page size |
| Servers | `https://` only; no internal hostnames in public specs |
| Errors | Generic error schema without stack traces |
| GraphQL | Disable introspection in production (or restrict), query depth/complexity limits, per-field authorization, persisted queries for public clients |

## Enforce at runtime

Gateway request validation against the spec (Kong/Apigee/AWS API Gateway request validators, Envoy/OPA policies, framework validators like FastAPI/pydantic, express-openapi-validator) — reject unknown fields and invalid types before business logic.

## Related skills

`api-inventory`, `api-authorization-testing`, `release-gate`

## References

- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- Spectral: https://github.com/stoplightio/spectral
- Spectral OWASP ruleset: https://github.com/stoplightio/spectral-owasp-ruleset
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
