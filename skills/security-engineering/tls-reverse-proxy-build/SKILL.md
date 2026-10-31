---
name: tls-reverse-proxy-build
description: Build a hardened TLS reverse proxy in front of internal applications with nginx (or Caddy/HAProxy) — TLS 1.2/1.3 with modern ciphers, automated certificates, HSTS and security headers, HTTP→HTTPS redirect, request size and rate limits, correct X-Forwarded-* handling, no version disclosure — and verify it with nginx -t, openssl and testssl.sh. Use when publishing a web application or admin interface, fixing TLS scan findings, or replacing an ad-hoc proxy config.
license: MIT
metadata:
  category: security-engineering
  version: "2.1.0"
  verification: documented
---

# TLS Reverse Proxy Build (nginx)

Follows `secure-build-workflow`. Not executed in this repository: nginx isn't available to the test suite. The verification commands are in section 3.

## 1. Requirements

Hostnames, backend address/port, certificate source (ACME via certbot/lego, internal CA), clients to support (modern only, or older devices too), upload sizes, WebSocket needs, which paths are admin-only (IP allowlist / SSO in front).

## 2. Configuration

`/etc/nginx/conf.d/app.conf` (nginx ≥ 1.25.1 for `http2 on;`):
```nginx
limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;

server {
    listen 80;
    listen [::]:80;
    server_name app.example.com;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name app.example.com;

    ssl_certificate     /etc/ssl/app/fullchain.pem;
    ssl_certificate_key /etc/ssl/app/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    server_tokens off;
    client_max_body_size 10m;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "frame-ancestors 'none'" always;

    location / {
        limit_req zone=perip burst=20 nodelay;
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;      # overwrite, don't append client-supplied values
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 60s;
    }

    location /admin/ {
        allow 10.20.0.0/24;
        deny all;
        proxy_pass http://127.0.0.1:8080;
    }
}
```
Notes:
- `add_header` in a `location` block discards inherited headers; repeat the headers or use an include file.
- Many public CAs, including Let's Encrypt in 2025, have ended OCSP. Enable `ssl_stapling` only if your CA still serves OCSP.
- HSTS `includeSubDomains`/`preload` affects every subdomain. Confirm they all serve HTTPS first.
- Backends listen only on 127.0.0.1 or a private interface (enforce with `host-firewall-build`).

## 3. Validate

```sh
sudo nginx -t
echo | openssl s_client -connect app.example.com:443 -servername app.example.com -tls1_1 2>&1 | grep -E 'alert|Cipher is'   # must fail
echo | openssl s_client -connect app.example.com:443 -servername app.example.com -tls1_3 2>/dev/null | grep -E 'Protocol|Cipher'
curl -sI https://app.example.com | grep -iE 'strict-transport|x-content-type|server:'
testssl.sh --severity LOW https://app.example.com
```
Test the admin allowlist from an outside address (expect 403) and confirm that a forged `X-Forwarded-For: 10.20.0.5` from outside does **not** pass. The `allow` directive uses `$remote_addr` unless `real_ip` is configured; if it is, set `set_real_ip_from` only for trusted proxies.

## 4. Roll out and operate

Reload with `nginx -s reload` after `nginx -t` (an existing config keeps serving if the new one fails). Automate renewal (`certbot renew --deploy-hook "systemctl reload nginx"`) and monitor expiry (`certificate-lifecycle`). Ship access and error logs to the SIEM (`web-server-log-analysis`), and consider a WAF (`waf-rule-tuning`).

## Related skills

`secure-build-workflow`, `certificate-lifecycle`, `waf-rule-tuning`, `web-server-log-analysis`, `host-firewall-build`

## References

- Mozilla SSL Configuration Generator: https://ssl-config.mozilla.org/
- nginx ngx_http_ssl_module: https://nginx.org/en/docs/http/ngx_http_ssl_module.html
- OWASP HTTP Security Response Headers Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- testssl.sh: https://testssl.sh/
