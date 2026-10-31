# Changelog

## 2.1.0 — 2026-10-31 (security engineering)

### Added
- `security-engineering` category: 9 skills that build deployable blue-team controls, all following one standard (`secure-build-workflow`: requirements, design, validation, isolated test, rollback, operation).
  - `host-firewall-build` (tested): nftables generator from a JSON policy.
    - It manages a single table atomically and never flushes other tables.
    - It refuses policies that would lock out administration.
    - Per-source rate limits and the required ICMPv6 are built in.
    - `netns_test.py` checks the ruleset with real TCP/UDP traffic in unprivileged network namespaces.
    - `safe_apply.sh` applies it with a detached auto-rollback timer.
  - `ssh-hardening-build` (tested): sshd drop-in generator with ML-KEM hybrid KEX, crypto lists intersected with the local OpenSSH, and `live_test.sh` against a live throwaway sshd.
  - `security-tool-development` (tested): secure Python tool scaffold with safe I/O and subprocess helpers, redaction, tests and hardened CI.
  - `cloud-firewall-build`, `tls-reverse-proxy-build`, `ids-deployment-build`, `log-shipping-build`, `hardening-automation-build` (documented).
- `engineering` install profile and `blue-team-engineering` plugin.
- 15 new tests (49 total). CI installs nftables and OpenSSH and enables unprivileged user namespaces.

### Fixed during testing
- Shell validation used locale-dependent `[a-z]` ranges, which reject valid names under `tr_TR`. Scripts now pin `LC_ALL=C`.
- The scaffold's `run()` accepted a shell string, because a string is iterable and each character is a str. It now requires a list or tuple.
- The SSH password check was rewritten to read the methods the server offers. A failed BatchMode login can never prove that passwords are disabled.

## 2.0.0 — 2026-10-31 (audit and rebuild)

### Audit findings on 1.0.0
- All 250 SKILL.md files were generated from one 48-line template. Only the description, one sentence and one "expected environment" line differed. There were no commands, queries, detection logic or real output templates. The validator passed them because it checked only length and two headings.
- Duplicated or overlapping skills: e.g. `artifact-provenance`/`slsa-provenance`, `sbom-review`/`sbom-generation`, `privilege-review`/`pam-review`, and the identity-hunting skills.
- Missing core areas: Windows event logs/Sysmon, Active Directory attacks and ADCS, Linux and macOS forensics, Kerberos, memory forensics, Zeek/Suricata, M365/Okta/Workspace/GitHub audit, MCP/agent security, deception, insider risk, web shells and WAF.
- Installer: no upgrade or incremental install (refused any existing manifest), no project scope, no rollback on partial copy, dry-run created the target directory, uninstall was all-or-nothing.
- No Claude Code plugin packaging. No handling of the skill-listing context budget.

### Changed
- Rebuilt the catalog: **253 skills / 49 categories**, every skill rewritten with domain-specific procedures, commands, detection logic, output templates and references. Old template skills were removed (backup kept outside the repo).
- `tools/claude_blue.py` rewritten:
  - strict frontmatter parser and portable-key enforcement;
  - related-skill, link and script reference checks;
  - ATT&CK v20 ID validation and a boilerplate detector;
  - catalog and marketplace generation, and rule extraction;
  - installer with profiles, project scope, incremental install, `--upgrade`, staged and verified copies, partial uninstall, root refusal and symlink safety.
- CI pins actions by SHA, sets `contents: read`, installs YARA/Sigma/tshark and audits its own workflow.

### Added
- 9 stdlib scripts with fixtures and tests: timeline merge, beacon scoring, .eml parsing, IOC extraction, GitHub Actions audit, Kubernetes RBAC audit, CloudTrail summary, IAM policy lint, password-spray detection.
- Tests: 34 unit tests, including embedded Sigma (`sigma check` + Splunk conversion), YARA compilation and tshark commands.
- `.claude-plugin/marketplace.json` with 12 plugins (`blue-team-<profile>` and `blue-team-all`). Passes `claude plugin validate`.
- `tools/profiles.json`, `tools/data/attack-enterprise.json`.

### Fixed
- ATT&CK references updated for v20 (Defense Evasion → Stealth/Defense Impairment; T1562 → T1685).
- 12 broken reference links replaced after checking all 687 unique URLs.

## 1.0.0 — 2026-10-30
Initial implementation (template-based; superseded).
