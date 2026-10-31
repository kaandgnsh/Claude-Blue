---
name: conditional-access-review
description: Review Microsoft Entra Conditional Access for gaps — MFA coverage for all users and apps, phishing-resistant MFA for admins, legacy authentication blocking, device compliance, token protection, risk-based policies, exclusions and report-only policies — using policy exports and sign-in log evidence. Use when assessing Entra ID security, troubleshooting why a sign-in wasn't challenged, or after an account takeover.
license: MIT
metadata:
  category: azure-security
  version: "2.0.0"
  verification: documented
---

# Conditional Access Review

## Export policies

```powershell
Connect-MgGraph -Scopes "Policy.Read.All"
Get-MgIdentityConditionalAccessPolicy -All | ConvertTo-Json -Depth 10 > ca-policies.json
```
Tools: Microsoft's CA templates / "What If", Maester (Pester-based Entra tests: `Invoke-Maester`), CISA ScubaGear for M365 baselines (`Invoke-SCuBA`).

## Baseline policy set (Microsoft guidance)

1. Require MFA for **all users, all resources** (exclude only break-glass accounts).
2. Require **phishing-resistant MFA** (FIDO2, Windows Hello for Business, certificate-based) for privileged roles (authentication strength).
3. **Block legacy authentication** (client apps: Exchange ActiveSync, other clients).
4. Require MFA for Azure management (Windows Azure Service Management API / Microsoft Admin Portals).
5. Require compliant or hybrid-joined device for sensitive apps or for admins.
6. Sign-in risk / user risk policies (Entra ID P2): require MFA / password change.
7. Block or restrict device code flow and authentication transfer where not needed.
8. Token protection (session binding) for supported apps where licensed.

## Gap analysis with sign-in evidence

```kusto
SigninLogs
| where TimeGenerated > ago(30d) and ResultType == "0"
| where AuthenticationRequirement == "singleFactorAuthentication"
| summarize count(), apps=make_set(AppDisplayName, 20) by UserPrincipalName, ClientAppUsed
| order by count_ desc
```
Shows real single-factor successes — each is a gap or an intended exclusion. Also check `ConditionalAccessStatus == "notApplied"`.

## Common weaknesses

- Exclusions for groups that grow (e.g., "MFA exclusions" with dozens of users), service accounts used interactively, trusted named locations covering whole ISP ranges, policies left in **report-only**, guest users excluded, "All cloud apps" missing for some policies, device platform conditions bypassable with unknown platforms.
- Break-glass accounts without alerting on use.

## Output

`Policy | State | Users/apps scope | Exclusions (count, justification) | Gap | Evidence (sign-ins) | Recommendation`

## Related skills

`entra-signin-investigation`, `authentication-policy-review`, `azure-rbac-review`, `token-theft-investigation`

## References

- Conditional Access policy templates: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policy-common
- Authentication strengths: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths
- Maester: https://maester.dev/
- CISA ScubaGear: https://github.com/cisagov/ScubaGear
