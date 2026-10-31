---
name: source-control-hardening
description: Harden GitHub/GitLab/Azure DevOps organizations and repositories — SSO and MFA enforcement, branch/ruleset protection, required reviews and CODEOWNERS, signed commits, secret scanning and push protection, third-party app access, deploy keys and PAT governance, audit log streaming. Use when assessing SCM security posture, onboarding a new org, or after a source-code or token leak.
license: MIT
metadata:
  category: devsecops
  version: "2.0.0"
  verification: documented
---

# Source Control Hardening

## Organization controls

| Control | GitHub | GitLab |
|---|---|---|
| SSO + MFA | SAML SSO / EMU, require 2FA | SAML group sync, enforce 2FA |
| Base permissions | Members: read or none | Default role minimal |
| Owners/admins | ≤ few, reviewed quarterly | Same |
| Third-party apps | OAuth app access restrictions; review GitHub Apps installations and permissions | Approved integrations |
| Tokens | Fine-grained PAT policy with approval & max lifetime; restrict classic PATs | PAT expiry enforcement |
| Audit | Audit log streaming to SIEM (incl. git events) | Audit events streaming |
| Secret scanning | Secret scanning + **push protection**, custom patterns | Secret detection + push rules |
| Actions/CI | Allowed actions list, read-only default token | Protected variables/runners |

## Repository controls

- Rulesets/branch protection on default and release branches: required PR reviews (≥ 1, ≥ 2 for critical), dismiss stale approvals, require review from CODEOWNERS, required status checks, block force-push and deletion, include administrators.
- CODEOWNERS covering `.github/workflows/`, CI config, IaC, auth code.
- Signed commits/tags where feasible (`git commit -S`, Sigstore gitsign).
- Deploy keys: read-only unless required; inventory and rotate.
- Archive or delete abandoned repos; watch public repository creation by members.

## Quick review commands (GitHub CLI)

```sh
gh api orgs/ORG --jq '{two_factor_requirement_enabled, default_repository_permission, members_can_create_public_repositories}'
gh api orgs/ORG/installations --jq '.installations[] | {app_slug, repository_selection, permissions}'
gh api repos/ORG/REPO/rulesets --jq '.[] | {name, enforcement, target}'
gh api repos/ORG/REPO/branches/main/protection 2>/dev/null | jq '{reviews: .required_pull_request_reviews, enforce_admins: .enforce_admins.enabled}'
```

## Related skills

`github-actions-hardening`, `github-audit-investigation`, `secret-scanning`, `pipeline-threat-model`

## References

- GitHub: Best practices for securing accounts and organizations: https://docs.github.com/en/code-security/securing-your-organization
- GitHub rulesets: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets
- OpenSSF Source Code Management Best Practices (SCM platform guide): https://best.openssf.org/SCM-BestPractices/
- CIS Software Supply Chain Security Guide: https://www.cisecurity.org/insights/white-papers/cis-software-supply-chain-security-guide
