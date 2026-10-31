---
name: release-gate
description: Define and operate security release gates in CI/CD — which checks block (new critical SAST/SCA/secret/IaC findings, unsigned artifacts, missing provenance), thresholds, exception workflow and metrics — so security is enforced without blocking delivery on legacy debt. Use when designing pipeline security policy, tuning a gate that blocks too much, or approving a release with open findings.
license: MIT
metadata:
  category: devsecops
  version: "2.0.0"
  verification: documented
---

# Security Release Gate

## Gate design principles

1. **Gate on new risk, report on old**: block PRs/releases that *introduce* critical findings; track existing backlog separately with SLAs.
2. **High-signal checks only** block; noisy checks warn until tuned.
3. **Exceptions are explicit** (ticket, approver, expiry) and visible in the pipeline log.
4. **Same policy everywhere** via reusable workflows/templates; changes to gate config require security review (CODEOWNERS).

## Typical gate matrix

| Check | Tool examples | Block when |
|---|---|---|
| Secrets | gitleaks, GitHub push protection, trufflehog | Any verified/live secret |
| SAST | Semgrep, CodeQL | New high/critical with confirmed rule precision |
| SCA | osv-scanner, Dependabot, Trivy | New dependency with KEV/critical reachable vuln, or malicious package |
| IaC | Checkov, Trivy config | New high/critical misconfig |
| Container image | Trivy, Grype | Critical fixable vulns in base image; image not from approved registry |
| Supply chain | cosign verify, SLSA provenance verify | Unsigned artifact or provenance mismatch at deploy |
| DAST (staging) | ZAP baseline | High-confidence high findings |
| Policy | OPA/Kyverno at deploy | Privileged workloads, latest tags |

## Exception record

`Finding | Release | Reason | Compensating control | Approver | Expiry | Ticket` — pipeline reads an allow-list file (in repo, CODEOWNERS-protected) keyed by finding fingerprint with expiry date; expired entries fail the gate.

## Metrics

Gate pass rate, mean time blocked, exceptions count/age, escaped vulnerabilities (found in prod that the gate should have caught).

## Related skills

`sast-triage`, `sca-dependency-risk`, `iac-scanning`, `artifact-signing`, `vuln-exception-review`

## References

- NIST SP 800-218 SSDF: https://csrc.nist.gov/pubs/sp/800/218/final
- OWASP DevSecOps Guideline: https://owasp.org/www-project-devsecops-guideline/
- OpenSSF Concise Guide for Developing More Secure Software: https://best.openssf.org/Concise-Guide-for-Developing-More-Secure-Software
