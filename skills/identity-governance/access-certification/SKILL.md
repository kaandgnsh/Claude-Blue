---
name: access-certification
description: Plan and run user access reviews/certifications — scope by risk (privileged, sensitive apps, external users), prepare clean entitlement data with context, reviewer selection, rubber-stamping controls, revocation tracking and audit evidence (SOX, SOC 2, ISO 27001, PCI). Use when an access review campaign is due, reviewers are approving everything, or auditors request certification evidence.
license: MIT
metadata:
  category: identity-governance
  version: "2.0.0"
  verification: documented
---

# Access Certification

## Campaign design

| Population | Frequency (typical) | Reviewer |
|---|---|---|
| Privileged/admin roles (IdP, cloud, AD Tier 0, databases) | Quarterly | Role/system owner + security |
| Financially significant systems (SOX) | Quarterly | Application owner |
| Sensitive data apps (PII, PHI, PCI) | Quarterly–semi-annual | Data owner |
| General SaaS / standard access | Annually | Manager |
| Guests/external users, service accounts | Quarterly | Sponsor / owner |

## Data preparation (most campaigns fail here)

- Pull entitlements from the **system of record** (not a stale IGA cache); include account status, last login/last use, entitlement description in business language, assignment source (role/birthright vs. request), HR status (active/leaver/mover), manager.
- Flag high-risk items: never used in 90 days, terminated owner, toxic combinations (`segregation-of-duties`), privileged.
- Remove noise: birthright entitlements managed by policy can be certified at the role level instead of per user.

Tools: Entra ID Access Reviews (incl. PIM role reviews, guest reviews), SailPoint/Saviynt/Okta Identity Governance, or spreadsheet exports for smaller systems with checksums for audit.

## Anti-rubber-stamping

Require decisions per item (no "approve all" for privileged), show usage data, measure reviewer approval speed (e.g., > 100 approvals in < 1 minute → flag), sample-check decisions, escalate non-responses (auto-revoke on non-response for low-risk entitlements where policy allows).

## Close the loop

Revocations ticketed and **verified** in the target system (re-pull after X days); evidence package: campaign scope, population extract (with timestamp/hash), decisions, revocation proof, exceptions with approver.

## Metrics

Completion %, revocation rate (very low may indicate rubber-stamping; very high indicates provisioning issues), time to revoke, repeat findings.

## Related skills

`privileged-access-review`, `segregation-of-duties`, `joiner-mover-leaver`, `audit-evidence-package`

## References

- Microsoft Entra Access Reviews: https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview
- NIST SP 800-53 Rev. 5 AC-2 Account Management: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- ISO/IEC 27001:2022 Annex A 5.18 Access rights (standard; purchase required)
