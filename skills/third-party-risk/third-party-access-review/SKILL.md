---
name: third-party-access-review
description: Review third-party access into your environment — vendor and contractor accounts, MSP/RMM tools, remote support sessions, B2B guest users, partner VPNs, API integrations, OAuth apps and cloud cross-account roles — for necessity, least privilege, MFA, monitoring and expiry. Use for periodic vendor access reviews, MSP security assessments, or after a supply-chain incident.
license: MIT
metadata:
  category: third-party-risk
  version: "2.0.0"
  verification: documented
---

# Third-Party Access Review

## Inventory access paths

| Path | Where to look |
|---|---|
| Named vendor/contractor accounts | IdP (user type, sponsor attribute), AD OUs, local app accounts |
| Guest users (B2B) | Entra `userType eq 'Guest'`, Google external sharing, Slack Connect |
| Remote access | VPN groups, ZTNA policies, jump hosts, remote support tools (TeamViewer, AnyDesk, BeyondTrust, ScreenConnect) |
| MSP/RMM | RMM agents installed on endpoints/servers (N-able, Kaseya, NinjaOne, ConnectWise) — effectively admin on every managed host |
| Cloud | AWS cross-account role trusts (`aws-iam-review`), Azure Lighthouse delegations, GCP external principals |
| Integrations | API keys issued to partners, OAuth apps (`oauth-app-review`), SFTP accounts, webhooks |
| Privileged delegation | Microsoft partner GDAP relationships, Google reseller access |

Quick checks:
```powershell
Get-MgUser -All -Filter "userType eq 'Guest'" -Property DisplayName,Mail,CreatedDateTime,SignInActivity | Select DisplayName,Mail,CreatedDateTime,@{n='LastSignIn';e={$_.SignInActivity.LastSignInDateTime}}
```
```sh
aws iam list-roles --query 'Roles[].{n:RoleName,trust:AssumeRolePolicyDocument.Statement[].Principal}' --output json | jq '.[] | select((.trust|tostring)|test("arn:aws:iam::[0-9]+:root"))'
```

## Criteria

Business sponsor and contract linkage; access limited to required systems and time (JIT approval for remote support); MFA enforced on vendor accounts (and for MSP tools); session recording for privileged vendor access; no shared vendor accounts; expiry dates; logging and alerting on vendor access outside approved windows; RMM tools restricted to approved ones (unexpected RMM installs are a common attacker TTP).

## Output

`Third party | Access path | Systems | Privilege | MFA | Sponsor | Last used | Expiry | Decision`

## Related skills

`vendor-security-assessment`, `access-certification`, `oauth-app-review`, `privileged-access-review`

## References

- CISA/NSA guidance on MSP security (AA22-131A): https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-131a
- CISA advisory on malicious use of RMM software (AA23-025A): https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
- Microsoft GDAP: https://learn.microsoft.com/en-us/partner-center/customers/gdap-introduction
