---
name: web-server-log-analysis
description: Analyze web server, reverse proxy, load balancer and WAF logs (Apache, Nginx, IIS, ALB, CloudFront, Azure Front Door) for exploitation attempts and successes — injection, path traversal, web shell access, scanning, credential attacks — distinguishing noise from successful compromise. Use when investigating a possible web application breach, triaging WAF alerts, or hunting web attacks.
license: MIT
metadata:
  category: web-application-defense
  version: "2.0.0"
  verification: documented
---

# Web Server Log Analysis

## Formats

Apache/Nginx combined: `ip - user [time] "METHOD /path?query HTTP/1.1" status bytes "referer" "user-agent"`. IIS W3C: `#Fields:` header defines columns (`cs-uri-stem`, `cs-uri-query`, `sc-status`, `c-ip`, `cs(User-Agent)`, `time-taken`). Cloud LBs/CDNs have their own (ALB access logs in S3, CloudFront standard logs, Front Door diagnostic logs). Behind proxies, the client IP is in `X-Forwarded-For` — make sure it's logged.

## Quick triage (combined log format)

```sh
# Top client IPs, status codes, paths
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head
awk '{print $9}' access.log | sort | uniq -c | sort -rn
# Suspicious patterns (encoded and plain)
grep -Ei "(union(%20|\+|\s)+select|information_schema|sleep\(|benchmark\(|%27|'--|\.\./|%2e%2e%2f|/etc/passwd|win\.ini|\$\{jndi:|<script|%3cscript|cmd=|exec=|/bin/sh|wget(%20|\+)|curl(%20|\+))" access.log | head -50
# Successful (2xx) requests to suspicious paths
grep -Ei "\.(php|jsp|aspx|ashx)(\?|\s)" access.log | awk '$9 ~ /^2/ {print $7}' | sort | uniq -c | sort -rn | head
# POSTs to static-content directories (web shell indicator)
awk '$6 ~ /POST/ && $7 ~ /(uploads|images|static|assets)\//' access.log
```

## Separating attempts from success

| Indicator | Suggests |
|---|---|
| 404/403 on scanner wordlists | Noise (still note source) |
| 200 with response size very different from baseline for that endpoint | Data returned (e.g., SQLi dump) |
| Requests to a new file path that returns 200, especially `.php/.jsp/.aspx` in upload dirs | Web shell (`web-shell-detection`) |
| Long `time-taken` with `sleep(`/`WAITFOR` payloads | Time-based injection working |
| Follow-on requests from the same IP to admin pages with 200 | Authenticated access achieved |
| Outbound connections from the web server shortly after a request (EDR/flow) | RCE callback |

## Pivot

Correlate with application logs, WAF logs, EDR on the server (child processes of `w3wp`/`httpd`/`nginx`/`java`), database audit (`db-exfiltration-investigation`).

## Related skills

`web-shell-detection`, `waf-rule-tuning`, `db-exfiltration-investigation`, `cve-technical-analysis`

## References

- Apache log formats: https://httpd.apache.org/docs/current/logs.html
- Nginx log module: https://nginx.org/en/docs/http/ngx_http_log_module.html
- IIS W3C logging: https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/sitedefaults/logfile/
- OWASP Web Security Testing Guide (attack patterns): https://owasp.org/www-project-web-security-testing-guide/
