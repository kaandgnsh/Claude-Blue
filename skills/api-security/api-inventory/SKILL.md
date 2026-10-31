---
name: api-inventory
description: Build and maintain an API inventory — discover documented, undocumented (shadow) and deprecated (zombie) APIs from gateways, traffic, code and specs; record owner, authentication, data classification and exposure. Use when starting an API security program, after acquisitions, or when OWASP API9 (improper inventory management) risk is suspected.
license: MIT
metadata:
  category: api-security
  version: "2.0.0"
  verification: documented
---

# API Inventory

## Discovery sources

| Source | Finds |
|---|---|
| API gateways / ingress (Apigee, Kong, AWS API Gateway, Azure APIM, NGINX/Envoy configs) | Published routes, auth policies |
| Traffic (WAF, load balancer, CDN logs, service mesh telemetry) | Endpoints actually called, including undocumented ones |
| Code & specs (OpenAPI/Swagger files, GraphQL schemas, route definitions, gRPC protos) | Intended surface |
| Cloud inventory (Lambda URLs, API Gateway stages, App Service, Cloud Run) | Forgotten deployments |
| External ASM (`external-attack-surface-review`) | Internet-exposed hosts with `/api`, `/swagger`, `/graphql`, `/v1` paths |
| Mobile apps (`mobile-app-security-review`) | Backend endpoints embedded in apps |

Examples:
```sh
aws apigateway get-rest-apis --query 'items[].{id:id,name:name,endpoint:endpointConfiguration.types}'
aws apigatewayv2 get-apis --query 'Items[].{id:ApiId,name:Name,protocol:ProtocolType,endpoint:ApiEndpoint}'
az apim api list --resource-group RG --service-name APIM -o table
# Endpoints seen in access logs (combined log format) vs. spec
awk '{print $7}' access.log | sed -E 's/[0-9]+/{id}/g; s/\?.*//' | sort | uniq -c | sort -rn | head -50
```

## Inventory record

`API | Base URL/host | Environment | Owner | Spec link/version | AuthN (OAuth2/OIDC, API key, mTLS, none) | Data classification | Exposure (internet/partner/internal) | Rate limits | Logging | Last seen in traffic | Status (active/deprecated/retire-by)`

## Findings to flag

- Endpoints in traffic but not in any spec (shadow APIs).
- Old versions (`/v1`) still reachable after `/v2` release (zombie APIs) — often lacking newer authorization fixes.
- Non-production environments exposed to the internet with real data.
- APIs with no owner or no authentication.

## Related skills

`api-schema-security`, `api-authorization-testing`, `external-attack-surface-review`, `shadow-it-discovery`

## References

- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OpenAPI Specification: https://spec.openapis.org/oas/latest.html
