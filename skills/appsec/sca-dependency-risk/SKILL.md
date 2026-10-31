---
name: sca-dependency-risk
description: Assess third-party dependency risk with software composition analysis — vulnerable versions (OSV, GitHub Advisory, NVD), reachability of vulnerable functions, license risk, maintainer health (OpenSSF Scorecard), transitive dependencies and safe upgrade paths. Use when reviewing dependency alerts (Dependabot, Snyk, osv-scanner), choosing a library, or prioritizing dependency upgrades.
license: MIT
metadata:
  category: appsec
  version: "2.0.0"
  verification: documented
---

# SCA and Dependency Risk

## Tools

```sh
osv-scanner scan source -r .                          # OSV database; lockfile-based (OSV-Scanner v2 syntax)
npm audit --omit=dev ; pip-audit -r requirements.txt ; govulncheck ./...   # ecosystem tools
trivy fs --scanners vuln,license .                    # filesystem/lockfiles
scorecard --repo=github.com/org/lib                   # OpenSSF Scorecard project health
```
`govulncheck` (Go) and some commercial tools report **reachability** — whether your code calls the vulnerable symbol.

## Triage questions

| Question | Effect |
|---|---|
| Is the vulnerable package in production runtime, or dev/test only? | Dev-only usually lower priority (but CI compromise risk) |
| Is the vulnerable function/feature used (reachability)? | Unreachable → lower priority, still upgrade in normal cycle |
| Exploit maturity: KEV/EPSS, public PoC? | Raises priority |
| Direct or transitive? | Transitive fixes may need override/resolution (`overrides` in npm, `constraints` in pip, `replace` in Go) |
| Fixed version available? Breaking changes? | Plan upgrade; read changelog |

## Choosing a new dependency

Check maintenance (recent releases, issue response), Scorecard score (branch protection, signed releases, CI tests), number of maintainers, download/popularity, install scripts (`preinstall/postinstall` in npm), license compatibility (copyleft GPL/AGPL in proprietary code needs legal review), and existing vulnerabilities.

## Output

`Package@version | Advisory (GHSA/CVE/OSV) | Severity/EPSS/KEV | Runtime? | Reachable? | Fix version | Breaking? | Decision | Owner`

## Related skills

`sbom-vulnerability-analysis`, `dependency-confusion-defense`, `malicious-package-response`, `vuln-prioritization`

## References

- OSV.dev and OSV-Scanner: https://osv.dev/ , https://google.github.io/osv-scanner/
- GitHub Advisory Database: https://github.com/advisories
- OpenSSF Scorecard: https://github.com/ossf/scorecard
- govulncheck: https://go.dev/doc/security/vuln/
