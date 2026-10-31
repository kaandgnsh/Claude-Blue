---
name: github-actions-hardening
description: Audit and harden GitHub Actions workflows — pwn-request patterns (pull_request_target/workflow_run with untrusted checkout), script injection from github.event fields, unpinned third-party actions, GITHUB_TOKEN permissions, OIDC to cloud, self-hosted runner risk — with a bundled tested auditor plus zizmor/actionlint. Use when reviewing CI workflows, responding to a compromised action, or setting org-wide Actions policy.
license: MIT
metadata:
  category: devsecops
  version: "2.0.0"
  verification: tested
---

# GitHub Actions Hardening

## Audit

```sh
python3 scripts/gha_audit.py .github/workflows/          # bundled heuristic auditor, JSON output, exit 1 on high/critical
python3 scripts/gha_audit.py wf.yml --fail-on medium
zizmor .github/workflows/                                 # dedicated Actions security linter (more complete)
actionlint                                                # syntax + shellcheck of run blocks
```
The bundled auditor is line-based (no YAML parser): treat it as a fast first pass and confirm with zizmor.

## Key risks and fixes

| Risk | Fix |
|---|---|
| `pull_request_target` / `workflow_run` + checkout of PR head → untrusted code with secrets and write token | Use `pull_request` for untrusted code; if `pull_request_target` is needed, never check out/execute PR code; split into unprivileged build + privileged comment job with artifacts treated as untrusted |
| Script injection: `run: echo "${{ github.event.pull_request.title }}"` | Pass via `env:` and reference `"$TITLE"`; never interpolate event fields into `run` |
| Unpinned actions (`@v4`, `@main`) — tag hijacks (e.g. tj-actions/changed-files, March 2025) | Pin to full commit SHA with a version comment; update via Dependabot/Renovate; restrict allowed actions at org level |
| Over-privileged `GITHUB_TOKEN` | Org default to read-only; per-workflow `permissions:` least privilege |
| Long-lived cloud keys in secrets | OIDC federation (`id-token: write`) with tight trust conditions on `sub` (repo, branch/environment) |
| Self-hosted runners on public repos | Don't; use ephemeral, isolated runners (ARC, just-in-time) with no persistent credentials |
| Secrets exposure in logs/artifacts | Mask, avoid `set -x`, scan artifacts; environments with required reviewers for deploy secrets |
| Cache poisoning | Don't share caches between untrusted PR and privileged workflows |

## AWS OIDC trust policy condition example

```json
"Condition": {
  "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
  "StringLike": { "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:environment:production" }
}
```
Never use `repo:my-org/*` or wildcard `sub` for deploy roles.

## Incident: compromised third-party action

Search all repos for the action and affected SHAs (`gh search code "uses: org/action" --owner my-org` or org-wide code search), review workflow run logs in the window for leaked secrets, rotate every secret available to those workflows, pin to a known-good SHA or remove.

## Related skills

`pipeline-threat-model`, `source-control-hardening`, `secret-leak-response`, `slsa-provenance`

## References

- GitHub security hardening for Actions: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
- GitHub Security Lab "Preventing pwn requests": https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
- zizmor: https://docs.zizmor.sh/
- actionlint: https://github.com/rhysd/actionlint
- CISA alert on tj-actions/changed-files (CVE-2025-30066): https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction
