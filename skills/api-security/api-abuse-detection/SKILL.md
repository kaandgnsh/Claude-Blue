---
name: api-abuse-detection
description: Detect and investigate API abuse and data exposure — enumeration/scraping, BOLA exploitation, token misuse, excessive data retrieval, unrestricted business flows — from gateway/WAF/application logs, and scope affected records. Use when an API shows anomalous traffic, a researcher reports an API data leak, or you need detections for OWASP API risks in production.
license: MIT
metadata:
  category: api-security
  version: "2.0.0"
  verification: documented
---

# API Abuse Detection and Investigation

## Log fields you need

Timestamp, client IP, authenticated principal (user ID / client ID / API key ID), tenant, method, route template (`/orders/{id}`) **and** concrete path, object IDs, status code, response size, latency, user agent, request ID. Without principal and object ID, BOLA scoping is impossible — fix logging first.

## Detection patterns

| Abuse | Signal |
|---|---|
| BOLA enumeration | One principal accessing many distinct object IDs not owned by them; sequential ID walks; high ratio of 403/404 then 200s |
| Scraping | High request rate per principal/IP across list endpoints; many pages; non-browser UAs; rotating IPs with same token |
| Token misuse | Same token from many IPs/ASNs/countries; token used after user offboarding; API key from unexpected networks |
| Excessive data | Response sizes far above baseline for an endpoint; `limit=10000` parameters |
| Business-flow abuse (API6) | Mass account creation, coupon redemption, ticket purchase bursts |
| Credential stuffing against auth APIs | `credential-stuffing-defense` |

Splunk example (BOLA candidate):
```spl
index=api route="/api/v2/orders/{id}" status=200 earliest=-24h
| stats dc(object_id) as objects dc(owner_id) as owners by principal_id
| where objects > 200 AND owners > 20 | sort -objects
```
Sentinel (APIM / App Gateway logs, columns depend on diagnostic category):
```kusto
ApiManagementGatewayLogs
| where TimeGenerated > ago(1d)
| summarize requests=count(), distinctUrls=dcount(Url), avgBytes=avg(ResponseSize) by CallerIpAddress, ApimSubscriptionId
| where distinctUrls > 500
```

## Incident scoping

1. Identify the vulnerable endpoint and the abusing principals/IPs.
2. Enumerate every object returned to those principals (object IDs + response sizes) → affected records and data fields.
3. Determine time window (first abusive request to fix deployment) and whether other principals exploited it.
4. Hand off to `privacy-incident-assessment` with counts and data types.

## Related skills

`api-authorization-testing`, `waf-rule-tuning`, `credential-stuffing-defense`, `data-exposure-investigation`

## References

- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP Automated Threats to Web Applications: https://owasp.org/www-project-automated-threats-to-web-applications/
- Azure API Management diagnostics logs: https://learn.microsoft.com/en-us/azure/api-management/monitor-api-management
