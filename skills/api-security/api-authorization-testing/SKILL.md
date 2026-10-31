---
name: api-authorization-testing
description: Test API authorization defensively — broken object-level authorization (BOLA/IDOR), broken function-level authorization, broken object property level authorization (mass assignment, excessive data exposure) and tenant isolation — with multi-user test matrices in authorized environments. Use when validating an API before release, investigating a suspected IDOR, or building automated authorization regression tests.
license: MIT
metadata:
  category: api-security
  version: "2.0.0"
  verification: documented
---

# API Authorization Testing

OWASP API Top 10 2023: API1 BOLA, API3 Broken Object Property Level Authorization, API5 Broken Function Level Authorization — the most common serious API flaws.

## Test setup (staging or authorized test tenant)

- At least two users per role in **two different tenants**: `userA@tenant1`, `userB@tenant1`, `userC@tenant2`, plus an admin and an unauthenticated client.
- Objects owned by each user (orders, documents, profiles).
- Capture requests from the app/spec (Burp/ZAP proxy, OpenAPI).

## Test matrix

| Test | Method | Expected |
|---|---|---|
| BOLA | Replay `GET/PUT/DELETE /orders/{idOfUserA}` with userB and userC tokens | 403/404, no data, logged |
| ID guessability | Are IDs sequential? UUIDs don't fix BOLA but reduce enumeration | Authorization still enforced |
| Function level | Call admin endpoints (`/admin/*`, `POST /users/{id}/roles`) with user token; try HTTP method switching (GET→DELETE) | 403 |
| Mass assignment | Add fields to updates (`"role":"admin"`, `"tenantId":"other"`, `"price":0`, `"isVerified":true`) | Ignored or rejected |
| Excessive data exposure | Inspect responses for fields not shown in UI (password hashes, tokens, other users' PII) | Only necessary fields |
| Tenant isolation | Use tenant-scoped IDs across tenants; filter params (`?tenant=`) manipulation | Denied |
| GraphQL | Query objects by ID via nested resolvers; introspection in prod | Per-resolver authorization |

Example with curl:
```sh
curl -s -H "Authorization: Bearer $TOKEN_USER_B" https://staging.example.com/api/v2/orders/1001 -o /dev/null -w '%{http_code}\n'
```
Automate as integration tests in CI (parametrized over user × object × endpoint) so regressions are caught.

## Fix guidance

Enforce authorization in a central layer using the authenticated principal (never IDs from the client to determine ownership), deny by default, response DTO allow-lists, schema validation rejecting unknown fields.

## Safety

Only in environments and accounts you are authorized to test; do not access real customer data — if a production IDOR is found during incident work, stop, record minimal evidence, and escalate.

## Related skills

`api-schema-security`, `secure-code-review`, `dast-baseline`, `api-abuse-detection`

## References

- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP Authorization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- OWASP WSTG Authorization Testing: https://owasp.org/www-project-web-security-testing-guide/
