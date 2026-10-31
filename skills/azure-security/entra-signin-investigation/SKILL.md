---
name: entra-signin-investigation
description: Investigate Microsoft Entra ID sign-ins — interactive and non-interactive logs, ResultType error codes, Conditional Access results, authentication details (MFA method), device and location, token-replay and AiTM indicators, risky sign-ins (Identity Protection) — with KQL and Graph. Use when a user account may be compromised, a risky sign-in alert fires, or sign-in anomalies need explaining.
license: MIT
metadata:
  category: azure-security
  version: "2.0.0"
  verification: documented
---

# Entra ID Sign-in Investigation

## Data

`SigninLogs` (interactive), `AADNonInteractiveUserSignInLogs` (token refresh, SSO — attackers with stolen refresh tokens appear here), `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`; `AADUserRiskEvents` / `AADRiskyUsers` (Identity Protection). Portal retention is limited — rely on Log Analytics/SIEM export.

## Core query

```kusto
let upn = "alice@contoso.com";
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d) and UserPrincipalName =~ upn
| extend Country = tostring(LocationDetails.countryOrRegion), City = tostring(LocationDetails.city),
         DeviceId = tostring(DeviceDetail.deviceId), Compliant = tostring(DeviceDetail.isCompliant),
         OS = tostring(DeviceDetail.operatingSystem), Browser = tostring(DeviceDetail.browser)
| project TimeGenerated, Type, IPAddress, Country, City, AppDisplayName, ResourceDisplayName, ResultType, ResultDescription,
          ConditionalAccessStatus, AuthenticationRequirement, MfaDetail, DeviceId, Compliant, OS, Browser, UserAgent,
          UniqueTokenIdentifier, SessionId, RiskLevelDuringSignIn
| order by TimeGenerated asc
```
(Some columns are `dynamic` in one table and `string` in the other; use `tostring(parse_json(...))` when unioning.)

## ResultType codes (common)

`0` success; `50126` invalid username/password; `50053` locked/smart lockout; `50074`/`50076` MFA required (strong auth); `500121` MFA failed/denied; `50140` "keep me signed in" interrupt; `53003` blocked by Conditional Access; `50158` external security challenge; `530032` blocked by security defaults/policy; `70044` session expired; `90095` admin consent required. Codes are documented in the AADSTS error reference.

## Compromise indicators

- Success from an IP/ASN/country never seen for the user, especially hosting/VPS providers, with a different device ID or no device ID.
- **AiTM phishing**: successful sign-in with MFA satisfied from attacker infrastructure seconds after the user's own sign-in to a phishing domain; followed by new inbox rules or MFA method registration.
- **Token replay**: non-interactive sign-ins with the same `SessionId` from a new IP/country while the device ID is absent; Identity Protection "Anomalous token" / "Token issuer anomaly".
- Sign-ins to unusual resources (Azure PowerShell, Graph Explorer, `Microsoft Azure CLI`) by non-admin users; user agents like `python-requests`, `axios`, `Go-http-client`.
- `ResultType 0` following many `50126` (spray success — `password-spray-detection`).

## Next steps

Correlate with `AuditLogs` (MFA method changes, app consents, role changes — `entra-audit-investigation`), `OfficeActivity`/`CloudAppEvents` for post-auth actions, and respond via `account-compromise-investigation`.

## Related skills

`entra-audit-investigation`, `token-theft-investigation`, `account-compromise-investigation`, `conditional-access-review`, `sentinel-kql-investigation`

## References

- Sign-in logs schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- AADSTS error codes: https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
- Identity Protection risk detections: https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
- Microsoft token theft playbook: https://learn.microsoft.com/en-us/security/operations/token-theft-playbook
