---
name: sast-triage
description: Run and triage static application security testing (Semgrep, CodeQL, SonarQube, Bandit, gosec, Brakeman) — reachability of sources to sinks, framework-provided protections, true/false positive decisions, suppression hygiene and custom rules. Use when a SAST scan produces findings to review, when tuning SAST noise in CI, or writing a custom rule for a recurring bug class.
license: MIT
metadata:
  category: appsec
  version: "2.0.0"
  verification: documented
---

# SAST Triage

## Running scanners

```sh
semgrep scan --config p/default --config p/owasp-top-ten --sarif -o semgrep.sarif .
semgrep scan --config p/secrets .                       # secrets ruleset
codeql database create db --language=python --source-root .
codeql database analyze db codeql/python-queries:codeql-suites/python-security-extended.qls --format=sarif-latest --output=codeql.sarif
bandit -r src/ -f json -o bandit.json                    # Python
gosec -fmt sarif -out gosec.sarif ./...                  # Go
```
Upload SARIF to the code host (GitHub code scanning, GitLab) so findings appear inline in PRs.

## Triage decision per finding

1. **Is the source attacker-controlled?** (HTTP input, file upload, message queue) — or constant/config/admin-only?
2. **Does data reach the sink unsanitized?** Follow the dataflow path the tool reports; check for validation, parameterization, framework auto-escaping (Django/Jinja2 autoescape, React JSX), allow-lists.
3. **Is the code reachable in production?** (dead code, tests, scripts, feature-flagged off).
4. **Decide**: TP (ticket with fix), FP (suppress with reason), won't-fix (risk-accepted with approver).

## Suppression hygiene

- Inline suppressions with a reason: `# nosemgrep: python.lang.security.audit.subprocess-shell-true -- command is constant`.
- Never suppress a whole rule globally because of one FP; tune the rule (path exclusions for tests, pattern-not for known safe wrappers).
- Review suppressions periodically.

## Custom Semgrep rule example

```yaml
rules:
  - id: corp-missing-ownership-check
    languages: [python]
    severity: WARNING
    message: Order fetched by ID without owner filter — possible IDOR (CWE-639)
    patterns:
      - pattern: Order.objects.get(id=$ID)
      - pattern-not-inside: |
          Order.objects.get(id=$ID, owner=$USER)
```

## Metrics

TP rate per rule (drop/tune rules < 20% TP), time-to-fix by severity, new vs. existing findings (gate only on **new** findings in PRs to avoid blocking on legacy debt).

## Related skills

`secure-code-review`, `sca-dependency-risk`, `release-gate`, `github-actions-hardening`

## References

- Semgrep docs: https://semgrep.dev/docs/
- CodeQL docs: https://codeql.github.com/docs/
- SARIF 2.1.0 (OASIS): https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
- OWASP Source Code Analysis Tools: https://owasp.org/www-community/Source_Code_Analysis_Tools
