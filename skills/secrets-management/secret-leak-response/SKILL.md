---
name: secret-leak-response
description: Respond to a leaked secret (API key, cloud key, token, password, private key, connection string) found in a public repo, logs, chat, paste site or container image — validate, revoke/rotate at the source, check for misuse in provider logs, purge copies, and prevent recurrence. Use when secret scanning, GitHub push protection, a researcher or a provider (AWS/GitHub/Slack) reports an exposed credential.
license: MIT
metadata:
  category: secrets-management
  version: "2.0.0"
  verification: documented
---

# Secret Leak Response

**Rotate first, investigate second.** Removing the secret from Git history does not un-leak it — public GitHub commits are scraped within minutes.

## Workflow

1. **Identify** the secret type, owner, system, privileges and the exposure (location, first commit time, public vs. internal, how long). Check validity without using it destructively (e.g., `trufflehog` verification, provider "whoami" calls like `aws sts get-caller-identity` with the key from an isolated host — only if authorized; many teams skip validation and just rotate).
2. **Revoke/rotate at the source**:
   | Secret | Action |
   |---|---|
   | AWS access key | `aws-credential-compromise` (deactivate, then delete) |
   | GCP SA key | `gcloud iam service-accounts keys disable/delete` (`gcp-service-account-keys`) |
   | Azure SP secret / storage key | Remove credential from app registration; `az storage account keys renew` |
   | GitHub PAT / app key | Revoke token; regenerate app private key |
   | Slack/Stripe/Twilio/etc. | Provider console revoke + reissue |
   | Database password | Change at DB, update app secrets store, restart consumers |
   | Private key / TLS cert | Revoke certificate, issue new key pair (`certificate-lifecycle`) |
   | SSH key | Remove from `authorized_keys`/IdP, issue new |
3. **Check for misuse** in provider logs from first exposure time (CloudTrail, GCP audit, GitHub audit, SaaS audit) and any data accessed.
4. **Purge copies**: remove from code (and history if needed: `git filter-repo --replace-text`), CI logs, artifacts, images (rebuild), tickets/chat; request cache removal (GitHub support for sensitive data in forks/PR refs).
5. **Prevent**: move to a secrets manager, enable push protection/pre-commit scanning (`secret-scanning`), use short-lived credentials (OIDC/workload identity).

## Record

`Secret | Owner | Exposure location | Exposed from–to | Public? | Revoked at | Misuse found | Copies purged | Root cause | Prevention`

## Related skills

`secret-scanning`, `aws-credential-compromise`, `ci-secret-review`, `vault-policy-review`

## References

- GitHub: Removing sensitive data from a repository: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository
- OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- git-filter-repo: https://github.com/newren/git-filter-repo
