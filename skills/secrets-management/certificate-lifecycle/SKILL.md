---
name: certificate-lifecycle
description: Manage TLS/PKI certificate lifecycle and risk — inventory (CT logs, scanners, internal CA), expiry monitoring, automation with ACME/cert-manager, key protection, revocation after key compromise, CA trust and shortening validity periods (47-day public TLS by 2029), plus TLS configuration checks with openssl and testssl.sh. Use when certificates expire unexpectedly, a private key leaks, planning PKI automation, or reviewing TLS posture.
license: MIT
metadata:
  category: secrets-management
  version: "2.0.0"
  verification: documented
---

# Certificate Lifecycle

## Inventory

- Public certs: Certificate Transparency (`curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u`), external scans.
- Internal: AD CS issued certificates database, cert-manager `Certificate` resources (`kubectl get certificates -A`), cloud certificate managers (ACM `aws acm list-certificates`, Azure Key Vault certificates, GCP Certificate Manager), load balancer and appliance configs.
- Record: subject/SANs, issuer, expiry, key type/size, location(s) deployed, owner, automation status.

## Check a live endpoint

```sh
echo | openssl s_client -connect www.example.com:443 -servername www.example.com 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
testssl.sh --severity MEDIUM https://www.example.com      # protocols, ciphers, known vulns
```
Targets: TLS 1.2+ (prefer 1.3), no SSLv3/TLS 1.0/1.1, forward-secret ciphers, HSTS, ECDSA P-256 or RSA ≥ 2048, OCSP stapling.

## Automation

ACME (Let's Encrypt, ZeroSSL, internal ACME CAs) via certbot/lego/cert-manager; CA/Browser Forum ballot SC-081 phases public TLS max validity down to 200 days (2026), 100 days (2027) and **47 days (2029)** — manual renewal will not scale. Monitor expiry (alert at 30/14/7 days).

## Key compromise response

1. Revoke the certificate at the CA (reason `keyCompromise`).
2. Generate a **new key pair** (never reuse the key), issue, deploy everywhere the old cert lived.
3. Investigate how the key leaked (`secret-leak-response`); internal CA key compromise → rebuild CA, distrust old root/intermediate (AD CS: remove from NTAuth — `adcs-security-review`).

## Related skills

`secret-leak-response`, `adcs-security-review`, `kms-key-review`, `external-attack-surface-review`

## References

- CA/Browser Forum Baseline Requirements: https://cabforum.org/working-groups/server/baseline-requirements/
- cert-manager: https://cert-manager.io/docs/
- testssl.sh: https://testssl.sh/
- Mozilla server-side TLS guidelines: https://wiki.mozilla.org/Security/Server_Side_TLS
