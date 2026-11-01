---
name: okta-log-investigation
description: Investigate Okta System Log events — authentication and MFA outcomes, session and token activity, admin and policy changes, factor resets, ThreatInsight detections, IdP/federation changes, support access — via the System Log API or SIEM. Use when an Okta account or org may be compromised, after help-desk social engineering, or when building Okta detections.
license: MIT
metadata:
  category: saas-security
  version: "2.2.0"
  verification: tested
---

# Okta System Log Investigation

## Query the API

```sh
curl -s -H "Authorization: SSWS $OKTA_TOKEN" \
  "https://ORG.okta.com/api/v1/logs?since=2025-03-01T00:00:00Z&filter=actor.alternateId+eq+%22alice@example.com%22&limit=1000" > alice.json
jq -r '.[] | [.published, .eventType, .outcome.result, .client.ipAddress, .client.geographicalContext.country, .client.userAgent.rawUserAgent] | @tsv' alice.json
```
Use pagination (`Link: rel="next"`). Store tokens in a vault; use a read-only admin role for investigations.

## Key event types

| Area | eventType |
|---|---|
| Authentication | `user.session.start`, `user.authentication.sso`, `user.authentication.auth_via_mfa`, `policy.evaluate_sign_on` |
| MFA / factors | `user.mfa.factor.activate`, `user.mfa.factor.deactivate`, `user.mfa.factor.reset_all`, `system.push.send_factor_verify_push`, `user.mfa.okta_verify.deny_push` |
| Account | `user.account.reset_password`, `user.account.update_password`, `user.lifecycle.*` |
| Admin | `user.account.privilege.grant`, `group.user_membership.add` (admin groups), `system.api_token.create`, `application.policy.sign_on.update`, `policy.rule.update` |
| Federation | `system.idp.lifecycle.create`, `system.idp.lifecycle.update` (rogue IdP → impersonation; seen in 2023 help-desk attacks) |
| Sessions | `user.session.impersonation.initiate` (support/admin impersonation), `user.session.clear` |
| Threats | `security.threat.detected` (ThreatInsight), `user.account.report_suspicious_activity_by_enduser` |

## Hunts

- Factor resets by help desk followed by sign-in from new IP/device within hours.
- New IdP created or routing rules changed (`policy.rule.update` on IdP discovery).
- API token creation by humans; admin role grants outside change windows.
- Same session ID (`authenticationContext.externalSessionId`) used from multiple IPs/ASNs (session hijack).

## Run the hunts on an export

```sh
python3 scripts/okta_hunts.py alice.json --reset-hours 24 --push-count 5 --push-minutes 10 > okta_findings.json
```

Accepts the API's JSON array (concatenate pages with `jq -s 'add'`) or JSON lines. Reports `factor-reset-then-new-ip`, `push-fatigue` (many pushes or denies, then an MFA success), `session-multi-ip` (one `externalSessionId` across ASNs), `rogue-idp`, `human-api-token` and `admin-grant`. Each finding carries the event time, user, IP and event type so you can pivot back into the System Log.

## Response

Clear user sessions and revoke tokens, reset factors (with verified identity), remove rogue IdPs/policies/admin grants, rotate API tokens, review downstream apps accessed via SSO during the window.

## Related skills

`account-compromise-investigation`, `mfa-fatigue-detection`, `token-theft-investigation`, `log-source-onboarding`

## References

- Okta System Log API: https://developer.okta.com/docs/reference/api/system-log/
- Okta event types catalog: https://developer.okta.com/docs/reference/api/event-types/
- Okta: Cross-tenant impersonation prevention and detection (2023): https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection
