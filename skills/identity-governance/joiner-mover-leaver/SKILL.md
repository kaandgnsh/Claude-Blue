---
name: joiner-mover-leaver
description: Assess and improve joiner-mover-leaver (JML) identity lifecycle processes — HR-driven provisioning, birthright roles, mover access removal, timely deprovisioning across IdP, AD, SaaS and non-SSO apps, contractor end dates — and test for gaps with HR-to-account reconciliation. Use when auditing identity lifecycle controls, after a leaver retained access, or designing automated provisioning.
license: MIT
metadata:
  category: identity-governance
  version: "2.0.0"
  verification: documented
---

# Joiner-Mover-Leaver (JML)

## Control objectives

| Event | Objective | Typical SLA |
|---|---|---|
| Joiner | Access provisioned from HR record with birthright role; extra access only via approved request | Day 1 |
| Mover | New role access granted **and old role access removed** (movers accumulate privilege) | ≤ 5 business days for removal |
| Leaver | All access disabled at termination time (immediately for involuntary/high-risk); sessions and tokens revoked; devices recovered | Same day / immediate |
| Contractor | End date mandatory; auto-disable at end date | On expiry |

## Reconciliation test (do this, don't just read the policy)

1. Export HR terminations for the last 90 days (name, employee ID, termination date/time).
2. Export accounts from IdP, AD, critical SaaS (including non-SSO apps with local accounts), VPN, cloud consoles, with status and last login.
3. Join on employee ID / email; find accounts **enabled after termination** or with **logins after termination** (the latter = incident candidate).
```sh
# Example with CSV exports: hr_leavers.csv(email,term_date) and app_accounts.csv(email,status,last_login)
python3 - <<'PY'
import csv
hr={r["email"].lower(): r["term_date"] for r in csv.DictReader(open("hr_leavers.csv"))}
for r in csv.DictReader(open("app_accounts.csv")):
    t=hr.get(r["email"].lower())
    if t and (r["status"].lower()=="enabled" or r["last_login"]>t):
        print(r["email"], "term", t, "status", r["status"], "last_login", r["last_login"])
PY
```
4. For movers: compare access before/after move for removal of old-department entitlements.

## Common gaps

Non-SSO apps with local accounts, shared accounts, service accounts tied to leavers, personal API tokens/PATs that survive SSO deprovisioning, OAuth tokens on mobile, mailbox delegation, cloud IAM users outside SSO, rehires reactivating old access.

## Output

`System | Leavers checked | Enabled after term | Logins after term | Avg time to disable | Root cause | Fix`

## Related skills

`orphan-account-review`, `access-certification`, `departing-employee-review`, `service-account-review`

## References

- NIST SP 800-53 Rev. 5 AC-2, PS-4 (Personnel Termination), PS-5 (Personnel Transfer): https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- Microsoft Entra lifecycle workflows: https://learn.microsoft.com/en-us/entra/id-governance/what-are-lifecycle-workflows
