---
name: pipeline-threat-model
description: Threat model a CI/CD pipeline end to end — source, build, dependencies, artifacts, deployment credentials and runtime — against OWASP Top 10 CI/CD Security Risks and SLSA threats, and produce prioritized controls. Use when designing or reviewing a build/deploy pipeline, after a supply-chain incident, or when assessing GitHub/GitLab/Jenkins/Azure DevOps security.
license: MIT
metadata:
  category: devsecops
  version: "2.0.0"
  verification: documented
---

# CI/CD Pipeline Threat Model

## Map the pipeline

Developer workstation → source repo (branches, PRs, reviews) → CI trigger → runner (hosted/self-hosted) → dependencies (registries, base images, actions/plugins) → build → artifacts (registry, bucket) → signing/provenance → deploy (credentials, environments, approvals) → production runtime. Mark who/what can change each stage and which credentials exist there.

## OWASP Top 10 CI/CD Security Risks

| ID | Risk | Questions |
|---|---|---|
| CICD-SEC-1 | Insufficient flow control | Can one person push to prod without review? Can CI config changes bypass review? |
| CICD-SEC-2 | Inadequate identity & access management | Stale accounts, shared accounts, broad org owners, external collaborators |
| CICD-SEC-3 | Dependency chain abuse | Confusion/typosquatting, unpinned deps (`dependency-confusion-defense`) |
| CICD-SEC-4 | Poisoned pipeline execution (PPE) | Can untrusted PRs modify pipeline definitions or scripts that run with secrets? |
| CICD-SEC-5 | Insufficient PBAC (pipeline-based access controls) | Do all jobs get all secrets? Are runners shared across trust levels? |
| CICD-SEC-6 | Insufficient credential hygiene | Long-lived secrets, secrets in logs, no rotation (prefer OIDC) |
| CICD-SEC-7 | Insecure system configuration | Unpatched Jenkins, exposed admin, default settings |
| CICD-SEC-8 | Ungoverned usage of 3rd-party services | OAuth apps / GitHub Apps with broad repo access |
| CICD-SEC-9 | Improper artifact integrity validation | Unsigned artifacts, no provenance verification at deploy (`artifact-signing`, `slsa-provenance`) |
| CICD-SEC-10 | Insufficient logging and visibility | Audit logs for SCM/CI not collected (`github-audit-investigation`) |

## Output

```
Pipeline <name> threat model <date>
Stages & credentials: <table>
Findings: <ID> <risk> <evidence> <severity> <control> <owner>
Top 5 controls: branch protection + CODEOWNERS on CI config | OIDC instead of static keys | pinned deps/actions | signed artifacts + deploy-time verification | SCM/CI audit logs to SIEM
```

## Related skills

`github-actions-hardening`, `source-control-hardening`, `slsa-provenance`, `threat-modeling`

## References

- OWASP Top 10 CI/CD Security Risks: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- SLSA threats: https://slsa.dev/spec/v1.0/threats
- CISA/NSA "Defending CI/CD Environments": https://media.defense.gov/2023/Jun/28/2003249466/-1/-1/0/CSI_DEFENDING_CI_CD_ENVIRONMENTS.PDF
