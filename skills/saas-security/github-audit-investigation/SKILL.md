---
name: github-audit-investigation
description: Investigate GitHub organization and enterprise audit logs — repository visibility changes, clones and archive downloads (git events), PAT/SSH key/deploy key creation, OAuth/GitHub App installs, Actions secrets and workflow changes, member and team permission changes — via the audit log API, gh CLI or streaming. Use when source code theft, token leaks, CI compromise or insider activity on GitHub is suspected.
license: MIT
metadata:
  category: saas-security
  version: "2.0.0"
  verification: documented
---

# GitHub Audit Investigation

## Query

```sh
gh api "/orgs/ORG/audit-log?phrase=actor:alice+created:>=2025-03-01&include=all&per_page=100" --paginate > alice.json
gh api "/orgs/ORG/audit-log?phrase=action:repo.access" --paginate      # visibility changes
gh api "/enterprises/ENT/audit-log?phrase=action:git.clone+repo:ORG/secret-repo&include=git"
jq -r '.[] | [(.["@timestamp"]/1000|todate), .action, .actor, .repo, .actor_ip // "", .user_agent // ""] | @tsv' alice.json
```
Git events (clone/fetch/push) are available for limited retention via API (`include=git`/`all`) — stream the audit log to a SIEM (Splunk, Azure, S3, Datadog) for longer retention. IP disclosure for actor IPs must be enabled in enterprise/org settings.

## Key actions

| Concern | Actions |
|---|---|
| Code exfiltration | `git.clone`, `git.fetch` volume per actor/token; `repo.download_zip`; forks of private repos (`repo.create` with fork) |
| Exposure | `repo.access` (visibility → public), `repo.transfer` |
| Credentials | `personal_access_token.*` (fine-grained requests/approvals), `public_key.create` (SSH), `repo.add_deploy_key` / `deploy_key.create`, `oauth_access.create` |
| Integrations | `integration_installation.create`, `oauth_application.*` |
| CI/CD | `workflows.*`, `repo.actions_secret`/`org.update_actions_secret` (names vary), `environment.*`, `protected_branch.destroy`/`.policy_override` |
| Membership | `org.add_member`, `org.update_member` (role → admin), `team.add_member`, `org.invite_member` |

Action names change over time — check GitHub's audit log events reference.

## Investigation steps

1. Identify the actor/token (`programmatic_access_type`, `token_id`, `hashed_token` fields) and source IPs.
2. List repos accessed/cloned and data volume; check for secrets in those repos (`secret-scanning`).
3. Check persistence: new keys, tokens, apps, members, webhooks (`hook.create` to external URLs).
4. Revoke tokens/keys/apps, rotate secrets in affected repos and CI, review branch protection overrides.

## Related skills

`source-control-hardening`, `github-actions-hardening`, `secret-leak-response`, `insider-threat-investigation`

## References

- Reviewing the audit log for your organization: https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization
- Audit log events for your organization: https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization
- Streaming the audit log: https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise
