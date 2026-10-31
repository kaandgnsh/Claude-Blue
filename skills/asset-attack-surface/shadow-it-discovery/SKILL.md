---
name: shadow-it-discovery
description: Discover unsanctioned SaaS, cloud accounts, AI tools and infrastructure — via proxy/DNS/CASB logs, SSO and OAuth grant data, expense and procurement records, cloud org enrollment, email sign-up notifications and external attack surface data — and bring them under governance without just blocking. Use when assessing unmanaged technology risk, preparing SaaS governance, or after finding unknown assets.
license: MIT
metadata:
  category: asset-attack-surface
  version: "2.0.0"
  verification: documented
---

# Shadow IT Discovery

## Sources

| Source | Finds |
|---|---|
| Proxy / SWG / DNS logs | SaaS domains used, volume of uploads, users |
| CASB (Defender for Cloud Apps, Netskope, Zscaler) | App catalog with risk scores, discovered apps |
| OAuth consent / token data | Apps users connected to corporate identities (`oauth-app-review`) |
| Email | Sign-up/verification emails from SaaS vendors to corporate addresses (search mail logs for "verify your email", "welcome to") |
| Finance | Expense reports and card transactions for software/cloud vendors |
| Cloud providers | Accounts/subscriptions/projects using corporate emails outside the organization (AWS Organizations, Azure tenant discovery, GCP org) |
| External ASM | Hosts under corporate domains not in inventory (`external-attack-surface-review`) |
| Browser extensions | Extension inventory via EDR/MDM |

DNS example (Zeek): `zeek-cut query < dns.log | awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head -100` → compare with sanctioned app list.

## Triage

For each discovered app/account: users and departments, data types uploaded, authentication (SSO? local passwords?), vendor security posture (`vendor-security-assessment`), business need.

Decide: **sanction** (onboard to SSO/SCIM, contract, DPA), **tolerate with controls** (no sensitive data, monitored), **replace** with an approved alternative, or **block** (with communication). Generative AI tools deserve explicit policy and an approved option (`llm-gateway-controls`).

## Output

`App/asset | Category | Users | Data | Auth | Risk | Decision | Owner`

## Related skills

`asset-inventory-reconciliation`, `oauth-app-review`, `vendor-security-assessment`, `llm-gateway-controls`

## References

- Microsoft Defender for Cloud Apps Cloud Discovery: https://learn.microsoft.com/en-us/defender-cloud-apps/set-up-cloud-discovery
- CIS Controls v8.1 Control 2 (Inventory of Software Assets): https://www.cisecurity.org/controls/inventory-and-control-of-software-assets
