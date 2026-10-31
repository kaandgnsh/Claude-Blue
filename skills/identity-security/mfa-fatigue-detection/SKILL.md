---
name: mfa-fatigue-detection
description: Detect and respond to MFA fatigue / push bombing and MFA bypass social engineering — bursts of denied or ignored push prompts followed by an approval, fraud reports, help-desk MFA resets — across Entra ID, Okta, Duo and others, and harden with number matching and phishing-resistant MFA. Use when users report unexpected MFA prompts, an MFA fraud alert fires, or after an MFA-approved compromise.
license: MIT
metadata:
  category: identity-security
  version: "2.0.0"
  verification: documented
---

# MFA Fatigue Detection

## Signals

| Platform | Signal |
|---|---|
| Entra ID | `SigninLogs` `ResultType` `500121` (strong auth failed/denied), `50074`; `AuthenticationDetails` with "MFA denied; user declined the authentication"; fraud report events (`User reported suspicious activity` in AuditLogs / Identity Protection risk "User reported suspicious activity") |
| Okta | `system.push.send_factor_verify_push` volume, `user.mfa.okta_verify.deny_push`, `user.authentication.auth_via_mfa` outcome FAILURE, and Okta's `user.mfa.attempt_bypass`; "Suspicious activity reported" events |
| Duo | Authentication log `result=denied`/`fraud`, `reason=user_marked_fraud` |

## Query (Entra ID)

```kusto
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType in ("500121", "50074", "50076")
| summarize prompts=count(), first=min(TimeGenerated), last=max(TimeGenerated), ips=make_set(IPAddress) by UserPrincipalName
| where prompts >= 5
| join kind=leftouter (SigninLogs | where ResultType == "0" and AuthenticationRequirement == "multiFactorAuthentication"
    | project SuccessTime=TimeGenerated, UserPrincipalName, SuccessIP=IPAddress) on UserPrincipalName
| where isnull(SuccessTime) or SuccessTime between (first .. (last + 1h))
```
A burst of denials then a success from the same (non-user) IP is a probable compromise.

## Related social engineering

Attackers call the help desk to reset MFA or register a new device (Scattered Spider–style). Correlate MFA method changes (`entra-audit-investigation`) with help-desk tickets; verify identity with strong procedures (video + manager confirmation, not just knowledge questions).

## Response

Treat approval-after-burst as compromise: revoke sessions, reset password (the attacker knew it), remove any new MFA methods, investigate (`account-compromise-investigation`). Notify the user that rejecting was right and to report.

## Hardening

Number matching + additional context (default in Microsoft Authenticator), Okta Verify number challenge, Duo Verified Push; rate-limit pushes; phishing-resistant MFA (FIDO2/passkeys, WHfB, CBA) for admins and high-risk users; disable SMS/voice where possible; strict help-desk reset verification.

## Related skills

`account-compromise-investigation`, `authentication-policy-review`, `entra-signin-investigation`, `okta-log-investigation`

## References

- MITRE ATT&CK T1621 Multi-Factor Authentication Request Generation: https://attack.mitre.org/techniques/T1621/
- Microsoft Authenticator number matching: https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match
- CISA guidance on number matching: https://www.cisa.gov/sites/default/files/publications/fact-sheet-implement-number-matching-in-mfa-applications-508c.pdf
