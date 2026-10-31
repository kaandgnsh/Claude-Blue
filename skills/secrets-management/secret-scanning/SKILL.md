---
name: secret-scanning
description: Detect hard-coded secrets in code, Git history, CI logs, container images and file shares with gitleaks, TruffleHog, GitHub secret scanning and push protection — tuning, verification of live secrets, baselines and pre-commit/CI integration. Use when setting up secret detection, scanning a repository or organization, or triaging secret-scanning alerts.
license: MIT
metadata:
  category: secrets-management
  version: "2.0.0"
  verification: documented
---

# Secret Scanning

## Tools

```sh
gitleaks git -v --report-format sarif --report-path gitleaks.sarif .        # full history (gitleaks v8.19+ subcommands; older: gitleaks detect)
gitleaks dir ./config                                                        # files without git
trufflehog git file://. --results=verified,unknown                          # verifies credentials against providers
trufflehog github --org=my-org --results=verified                            # org-wide (needs token)
trufflehog docker --image ghcr.io/org/app:1.4.2
```
Pre-commit hook (`.pre-commit-config.yaml`):
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.24.0
    hooks:
      - id: gitleaks
```
GitHub: enable secret scanning + **push protection** org-wide; add custom patterns for internal token formats; validity checks for supported partners.

## Triage

1. **Live?** Verified/valid secrets are P1 → `secret-leak-response`.
2. **Real or test?** Example keys (`AKIAIOSFODNN7EXAMPLE`), fixtures, placeholders → allowlist precisely (`.gitleaks.toml` `[allowlist]` with paths/regexes, or `# gitleaks:allow` inline).
3. **Where else?** If it's in history, it's in every clone and fork.
4. **Owner** from `git log -S'<fragment>' --all` / blame.

## Coverage beyond Git

CI logs and artifacts, container image layers, IaC state files (`terraform.tfstate` often holds plaintext secrets), wikis/Confluence, Slack/Teams exports, S3 buckets, endpoint config files (`.env`, `.npmrc`, `.aws/credentials`).

## Metrics

New secrets per month, mean time to revoke, push-protection bypasses (review each), repos without scanning.

## Related skills

`secret-leak-response`, `ci-secret-review`, `source-control-hardening`, `release-gate`

## References

- gitleaks: https://github.com/gitleaks/gitleaks
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- GitHub secret scanning: https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning
- GitHub push protection: https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection
