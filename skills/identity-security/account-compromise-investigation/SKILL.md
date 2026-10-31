---
name: account-compromise-investigation
description: Investigate and remediate a suspected compromised user account across IdP (Entra ID, Okta, Google, AD), email, SaaS and endpoints — confirm compromise, establish initial access, enumerate attacker actions and persistence, and perform a complete credential and session reset. Use when a user reports suspicious activity, an identity risk alert fires, or phishing credentials were submitted.
license: MIT
metadata:
  category: identity-security
  version: "2.0.0"
  verification: documented
---

# Account Compromise Investigation

## 1. Confirm

Review 14–30 days of sign-ins (`entra-signin-investigation` / Okta System Log / Google login audit): new IPs/ASNs/countries, devices, user agents, MFA method used, impossible travel, success after failures, token-replay patterns. Ask the user (out of band) about travel/new devices — but verify their answer with evidence.

## 2. Initial access

Phishing (look for clicks in `UrlClickEvents`/proxy right before the anomalous sign-in), AiTM proxy (attacker IP sign-in with MFA satisfied), password spray/stuffing, infostealer on a personal or corporate device (session cookie theft), MFA fatigue, help-desk social engineering (password/MFA reset tickets — check the ITSM system), OAuth consent.

## 3. Attacker actions & persistence checklist

- [ ] MFA methods added/changed (phone, authenticator, FIDO key) — `entra-audit-investigation`
- [ ] Mailbox rules, forwarding, delegates (`mailbox-compromise`)
- [ ] OAuth app consents (`oauth-app-review`)
- [ ] New devices registered/joined (Entra device registration, Intune enrollment)
- [ ] Files accessed/shared/downloaded (SharePoint/OneDrive `FileAccessed`, `FileDownloaded`, `SharingSet`, Google Drive audit)
- [ ] Emails sent (internal phishing, BEC)
- [ ] Privileged actions (role changes, app registrations) if the user had admin rights
- [ ] VPN/VDI sessions and endpoint logons using the credentials
- [ ] SaaS apps accessed via SSO from the attacker session

## 4. Remediate (coordinated)

1. Disable sign-in (temporarily) **or** reset password + require re-registration if attacker added MFA.
2. Revoke sessions/refresh tokens: Entra `Revoke-MgUserSignInSession`; Okta "Clear user sessions" (+ revoke OAuth tokens); Google "Sign-out user" + reset; AD: reset password (Kerberos tickets persist until expiry — purge on endpoints or wait; consider disabling).
3. Remove attacker MFA methods, devices, rules, consents.
4. If infostealer suspected: reimage device; reset **all** credentials saved in browsers on it.
5. Re-enable with phishing-resistant MFA where possible; monitor 30 days.

## Output

Timeline, initial access vector (confidence), attacker actions list, data accessed, persistence removed, credentials rotated, residual risk, notification needs (`privacy-incident-assessment`).

## Related skills

`entra-signin-investigation`, `token-theft-investigation`, `mailbox-compromise`, `okta-log-investigation`, `mfa-fatigue-detection`

## References

- Microsoft compromised and malicious applications / identity playbooks: https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks
- Okta User Sessions API (clear sessions, revoke tokens): https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserSessions/
- CISA phishing-resistant MFA: https://www.cisa.gov/resources-tools/resources/implementing-phishing-resistant-mfa
