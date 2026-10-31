---
name: password-spray-detection
description: Detect and respond to password spraying, credential stuffing and brute force against AD, Entra ID, Okta, VPN and SSO — distinct-user failure counts per source, low-and-slow distributed sprays, success-after-spray — with a bundled tested detector and SIEM queries. Use when lockouts spike, IdP risk alerts fire, or you need detections for credential-guessing attacks.
license: MIT
metadata:
  category: identity-security
  version: "2.0.0"
  verification: tested
---

# Password Spray Detection

## Patterns

| Attack | Shape |
|---|---|
| Password spray (T1110.003) | One/few passwords × many users; few attempts per user (stays under lockout); one or many source IPs |
| Credential stuffing (T1110.004) | Leaked user:password pairs; many users, ~1 attempt each, often residential proxies |
| Brute force (T1110.001) | Many passwords × one user |

## Bundled detector

```sh
# CSV columns: ts,user,src,outcome  (outcome success|failure)
python3 scripts/spray_detect.py auth.csv --window 3600 --spray-users 10 --brute-attempts 20
```
Outputs flagged sources and **successful logons from flagged sources** (exit code 1 if any) — those accounts are likely compromised. Export to CSV from your SIEM with the four columns.

## SIEM queries

Entra ID:
```kusto
SigninLogs
| where TimeGenerated > ago(1d) and ResultType in ("50126", "50053")
| summarize users=dcount(UserPrincipalName), attempts=count() by IPAddress, bin(TimeGenerated, 1h)
| where users >= 10
| join kind=inner (SigninLogs | where ResultType == "0" | project SuccessTime=TimeGenerated, IPAddress, UserPrincipalName) on IPAddress
```
Windows DCs (4625/4771):
```spl
index=wineventlog (EventCode=4625 OR (EventCode=4771 Failure_Code=0x18)) earliest=-24h
| bin _time span=1h | stats dc(user) as users count by _time, src_ip | where users >= 10
```
Okta: `eventType eq "user.session.start" and outcome.result eq "FAILURE"` grouped by `client.ipAddress`; Okta also emits ThreatInsight events (`security.threat.detected`).

## Distributed / low-and-slow sprays

Group by **password-failure timing across the tenant** rather than IP: spikes of `50126` across many users in short windows, common user agent/ASN, or failures for non-existent users (`50034` in Entra, `0xC0000064` in AD) that indicate username enumeration lists.

## Response

1. Block offending IPs/ASNs at IdP/WAF (temporary), enable/raise smart lockout.
2. For each success-after-spray: treat as compromised (`account-compromise-investigation`) — reset, revoke sessions, review MFA registration.
3. Check whether MFA was required for those sign-ins; close single-factor paths (legacy auth, excluded users) — `conditional-access-review`.
4. Banned-password lists (Entra Password Protection), passwordless/phishing-resistant MFA.

## Related skills

`account-compromise-investigation`, `credential-stuffing-defense`, `conditional-access-review`, `correlation-rule-design`

## References

- MITRE ATT&CK T1110.003: https://attack.mitre.org/techniques/T1110/003/
- Microsoft password spray investigation playbook: https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray
- Entra smart lockout: https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout
