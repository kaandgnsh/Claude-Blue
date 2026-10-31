---
name: token-theft-investigation
description: Investigate session token and cookie theft — adversary-in-the-middle phishing (Evilginx-style), infostealer-harvested cookies, refresh-token replay, OAuth device-code phishing, pass-the-cookie — and contain by revoking sessions and binding tokens. Use when MFA-protected accounts are compromised without password or MFA failures, Identity Protection flags anomalous tokens, or infostealer malware hit a device.
license: MIT
metadata:
  category: identity-security
  version: "2.0.0"
  verification: documented
---

# Token Theft Investigation

## Theft mechanisms

| Mechanism | Evidence |
|---|---|
| AiTM phishing proxy | User clicks link to look-alike domain → proxy relays real login + MFA → attacker receives session cookie; sign-in from attacker IP with MFA "satisfied by claim in token"/MFA completed, often seconds after the user's own sign-in |
| Infostealer (Lumma, RedLine-family, macOS stealers) | Malware execution on device → browser cookie DBs read → later sign-ins from new IPs without interactive auth; check EDR for stealer execution, `Login Data`/`Cookies` access |
| Device code phishing | Sign-in with `AuthenticationProtocol == "deviceCode"` for a user who doesn't use CLI tools; attacker-supplied codes via chat/email (Storm-2372 style) |
| Refresh token replay | `AADNonInteractiveUserSignInLogs` with the same `SessionId`/`UniqueTokenIdentifier` lineage from a new IP/ASN and no device ID |
| OAuth consent phishing | `oauth-app-review` |

## Queries (Entra ID)

```kusto
// Same session used from multiple IPs/countries
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d) and ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize ips=make_set(IPAddress, 20), countries=make_set(Country), apps=make_set(AppDisplayName, 20) by UserPrincipalName, SessionId
| where array_length(countries) > 1 or array_length(ips) > 3

// Device code flow sign-ins
SigninLogs | where AuthenticationProtocol == "deviceCode" | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, UserAgent
```
Identity Protection risk detections: *Anomalous token*, *Token issuer anomaly*, *Attacker in the Middle*, *Unfamiliar sign-in properties*.

## Contain

1. **Revoke refresh tokens/sessions** (`Revoke-MgUserSignInSession`; Okta clear sessions + revoke tokens; Google sign-out) — a password reset alone may not invalidate existing sessions everywhere.
2. Block attacker IPs/infrastructure; take down phishing domain (registrar/hosting abuse).
3. Infostealer: isolate and reimage device; rotate **all** credentials and sessions stored in that browser profile (corporate and SaaS).
4. Hunt for other victims of the same AiTM domain (`phishing-campaign-scope`).

## Prevent

Phishing-resistant MFA (FIDO2/passkeys bound to origin), compliant-device Conditional Access, **token protection** (sign-in session token binding) for supported apps, Continuous Access Evaluation, block device code flow where unused, short session lifetimes for admins.

## Related skills

`account-compromise-investigation`, `entra-signin-investigation`, `phishing-triage`, `conditional-access-review`, `macos-triage`

## References

- Microsoft token theft playbook: https://learn.microsoft.com/en-us/security/operations/token-theft-playbook
- Token protection in Conditional Access: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection
- MITRE ATT&CK T1539 Steal Web Session Cookie: https://attack.mitre.org/techniques/T1539/
- MITRE ATT&CK T1550.004 Web Session Cookie: https://attack.mitre.org/techniques/T1550/004/
