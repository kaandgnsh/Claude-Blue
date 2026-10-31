---
name: dast-baseline
description: Run and interpret dynamic application security testing — OWASP ZAP baseline/full/API scans, nuclei, authenticated scanning, CI integration — with safe scope, and triage findings (headers, cookies, injection, misconfiguration) into fixes. Use when testing a web app or API in staging, adding DAST to a pipeline, or validating fixes for web vulnerabilities.
license: MIT
metadata:
  category: appsec
  version: "2.0.0"
  verification: documented
---

# DAST Baseline

## ZAP scans (Docker)

```sh
# Passive baseline: spiders and reports passive findings, no attacks — safe for most environments
docker run --rm -v "$(pwd)":/zap/wrk:rw -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://staging.example.com -r baseline.html -J baseline.json
# API scan from an OpenAPI definition (active rules — staging only)
docker run --rm -v "$(pwd)":/zap/wrk:rw -t ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t /zap/wrk/openapi.yaml -f openapi -r api.html
# Full scan (active attacks) — staging only, with approval
docker run --rm -v "$(pwd)":/zap/wrk:rw -t ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py -t https://staging.example.com -r full.html
```
Tune with a rules file (`-c rules.tsv`) to set rules to IGNORE/WARN/FAIL for CI gating. Authenticated scans: ZAP context with authentication script / headers (`-z "-config replacer.full_list(0).replacement=Bearer <token>"`) — use a dedicated low-privilege test account.

## Triage common findings

| Finding | Real issue? |
|---|---|
| Missing `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options` | Hardening gaps; prioritize CSP for apps with XSS risk and HSTS for all HTTPS |
| Cookie without `Secure`/`HttpOnly`/`SameSite` | Real for session cookies |
| Reflected XSS / SQLi (active) | Verify manually with the request/response evidence; often true when reproducible |
| "Application error disclosure" | Stack traces → fix error handling |
| Vulnerable JS library | Map to SCA process |
| Information disclosure (server banners) | Low |

## Safety

Active scans send attack payloads: run only against staging or authorized targets, never production without explicit approval; they can create junk data, trigger emails, lock accounts, or stress services. Exclude logout and destructive endpoints (`DELETE`, admin actions) from scope.

## Related skills

`secure-code-review`, `api-authorization-testing`, `release-gate`, `waf-rule-tuning`

## References

- ZAP Docker packaged scans: https://www.zaproxy.org/docs/docker/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
