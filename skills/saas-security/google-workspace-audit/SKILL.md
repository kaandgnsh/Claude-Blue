---
name: google-workspace-audit
description: Investigate and assess Google Workspace — Admin console audit logs (Login, Admin, Drive, Gmail, OAuth Token, SAML, Devices), Reports API/GAM, security investigation tool, external sharing, admin role and 2SV posture. Use when investigating a Workspace account compromise or data leak, or reviewing Workspace security configuration.
license: MIT
metadata:
  category: saas-security
  version: "2.0.0"
  verification: documented
---

# Google Workspace Audit

## Log sources (Reporting → Audit and investigation)

| Log | Key events |
|---|---|
| User log events (login) | `login_success`, `login_failure`, `suspicious_login`, `2sv_disable`, `account_disabled_hijacked`, `gov_attack_warning` |
| Admin log events | `GRANT_ADMIN_PRIVILEGE`, `CREATE_ROLE`, `CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT`, `TOGGLE_*` settings, `CREATE_DATA_TRANSFER_REQUEST` |
| Drive log events | `download`, `view`, `change_user_access`, `change_document_visibility` (public/anyone with link), `copy` |
| Gmail log events | Delivery, forwarding/filter changes (`email_forwarding_change` in user settings events) |
| OAuth Token log events | `authorize` (new app consent with scopes), `activity` |
| SAML log events | SSO to third-party apps |
| Rules / DLP | Rule triggers |

## Query via API / GAM

```sh
# GAM (GAMADV-XTD3) examples
gam report login user alice@example.com start -30d
gam report drive user alice@example.com event download start -7d
gam report admin start -30d event GRANT_ADMIN_PRIVILEGE
gam report token start -30d                                # OAuth grants
gam user alice@example.com show filters ; gam user alice@example.com show forwards
gam all users print tokens                                 # tokens per user (app, scopes)
```
Reports API: `GET https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?startTime=...`. Workspace logs can be exported to BigQuery (Enterprise editions) for SIEM-scale queries.

## Posture checks

2-Step Verification enforced (security keys for admins — Advanced Protection Program for super admins), number of super admins (2–4), less-secure apps/legacy access disabled, external sharing defaults (warn/restrict, no "anyone with the link" default), third-party app access control (API controls → trusted/limited/blocked apps), Gmail forwarding to external disabled or monitored, context-aware access for admins.

## Investigation flow

Login events (IPs/user agents) → OAuth grants and filters/forwarding (persistence) → Drive downloads/sharing (exfiltration) → admin events (if privileged). Remediate: reset password, sign out sessions, revoke tokens (`gam user x deprovision` revokes tokens/app passwords/backup codes — use with care), remove filters/forwards, revert sharing.

## Related skills

`oauth-app-review`, `account-compromise-investigation`, `data-exposure-investigation`

## References

- Workspace audit and investigation: https://support.google.com/a/answer/9725685
- Reports API: https://developers.google.com/admin-sdk/reports/v1/get-start/getting-started
- GAMADV-XTD3: https://github.com/taers232c/GAMADV-XTD3
- CISA SCuBA Google Workspace baselines: https://github.com/cisagov/ScubaGoggles
