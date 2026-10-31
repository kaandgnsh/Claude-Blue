---
name: credential-stuffing-defense
description: Detect and mitigate credential stuffing and account takeover against customer-facing login, registration and password-reset endpoints — traffic signals (distributed IPs, residential proxies, high failure rates, user-agent patterns), bot management, rate limiting, breached-password checks, MFA/passkeys, and response for compromised customer accounts. Use when login failures spike, customers report account takeovers, or designing consumer authentication defenses.
license: MIT
metadata:
  category: web-application-defense
  version: "2.0.0"
  verification: documented
---

# Credential Stuffing Defense

## Signals

| Signal | Detail |
|---|---|
| Failure ratio | Login failure rate across the app rises sharply (e.g., > 80% failures vs. normal 10–20%) |
| Unique usernames per IP/ASN/fingerprint | Many accounts tried, ~1 attempt each |
| Distributed sources | Thousands of IPs, residential proxy ASNs, data-center ASNs |
| Uniform client | Same TLS fingerprint (JA3/JA4), headless browser markers, same user agent across "different" users |
| Non-existent usernames | High rate of unknown-user failures (list-based attack) |
| Success then changes | Successful logins followed by email/phone/password changes, payout or gift-card redemption |

Example (Splunk, app auth logs):
```spl
index=app_auth action=login earliest=-1h
| stats count(eval(result="failure")) as fails count(eval(result="success")) as wins dc(username) as users by src_asn
| eval fail_ratio=fails/(fails+wins) | where users > 50 AND fail_ratio > 0.8 | sort -users
```

## Mitigations (layered)

1. **Bot management / WAF**: managed bot rules (AWS WAF Bot Control / ATP, Cloudflare Bot Management, Akamai), challenge suspicious clients.
2. **Rate limits** per IP, per account, per device fingerprint, and globally on auth endpoints; progressive delays rather than hard lockouts (lockouts can be abused for DoS).
3. **Breached-password screening** at signup/reset/login (k-anonymity range API: `https://api.pwnedpasswords.com/range/<first5 SHA-1 chars>`).
4. **MFA / passkeys** for customers; risk-based step-up for new device + sensitive actions.
5. **Uniform responses** to avoid username enumeration (same message and timing for unknown user vs. bad password; protect password-reset and registration endpoints too).
6. **Monitoring** of post-login sensitive actions.

## Response to confirmed takeovers

Reset affected customer credentials and sessions, notify customers, reverse fraudulent transactions where possible, block attacker infrastructure, review for data access (privacy assessment), and look for the credential source (third-party breach lists).

## Related skills

`password-spray-detection`, `waf-rule-tuning`, `api-abuse-detection`, `privacy-incident-assessment`

## References

- OWASP Credential Stuffing Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html
- OWASP Automated Threats (OAT-008 Credential Stuffing): https://owasp.org/www-project-automated-threats-to-web-applications/
- Have I Been Pwned Pwned Passwords API: https://haveibeenpwned.com/API/v3#PwnedPasswords
- MITRE ATT&CK T1110.004: https://attack.mitre.org/techniques/T1110/004/
