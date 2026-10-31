---
name: ci-secret-review
description: Review how CI/CD systems store and expose secrets — GitHub Actions secrets/environments, GitLab CI variables, Jenkins credentials, Azure DevOps variable groups, CircleCI contexts — scoping per environment, fork/PR exposure, log masking, OIDC replacement of static cloud keys, and runner persistence. Use when auditing pipelines for credential exposure or after a CI compromise.
license: MIT
metadata:
  category: secrets-management
  version: "2.0.0"
  verification: documented
---

# CI Secret Review

## Inventory

```sh
gh secret list --org ORG ; gh secret list -R ORG/REPO ; gh api repos/ORG/REPO/environments --jq '.environments[].name'
gh api orgs/ORG/actions/secrets --jq '.secrets[] | {name, visibility}'
# GitLab: Settings > CI/CD > Variables (API: GET /projects/:id/variables, GET /groups/:id/variables)
```
Jenkins: Credentials plugin stores (global vs. folder scope), who can configure jobs (can exfiltrate any credential used by the job).

## Review points

| Area | Good practice |
|---|---|
| Scope | Deploy secrets in **environments** with required reviewers and branch restrictions; not repo/org-wide |
| Untrusted code | Secrets never available to workflows triggered by forks/untrusted PRs (`github-actions-hardening`); GitLab protected variables only on protected branches |
| Static cloud keys | Replace with OIDC federation (GitHub/GitLab → AWS/Azure/GCP) with tight subject claims |
| Masking | Masked/protected variables; avoid echoing; `set +x`; structured secrets (JSON) aren't masked reliably — split them |
| Runners | Ephemeral runners; self-hosted runners don't keep `~/.aws`, Docker credentials or workspace between jobs |
| Artifacts & caches | No secrets written to artifacts, caches, or images |
| Rotation | Owners and rotation dates; remove unused secrets (last used where the platform reports it) |
| Third-party actions/plugins | Pinned; minimal; they see the secrets passed to them |

## Exposure check after incident

Search job logs in the window for secret patterns; list which secrets each compromised workflow/job could access; rotate all of them (`secret-leak-response`).

## Related skills

`github-actions-hardening`, `pipeline-threat-model`, `secret-leak-response`, `secret-scanning`

## References

- GitHub: Using secrets in GitHub Actions: https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions
- GitHub OIDC: https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect
- GitLab CI/CD variables security: https://docs.gitlab.com/ci/variables/
- OWASP Top 10 CI/CD Security Risks (CICD-SEC-6): https://owasp.org/www-project-top-10-ci-cd-security-risks/
