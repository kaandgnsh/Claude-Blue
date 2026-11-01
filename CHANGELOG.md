# Changelog

## 2.2.0 — 2026-11-01 (automation, testing, verification)

### Added
- `security-automation` category (6 skills): `soar-playbook-design` (tested; `playbook_lint.py` checks a vendor-neutral step graph for dangling and unreachable steps, non-terminating paths, unbounded loops, decisions without a default, disruptive actions without approval/rollback/idempotency key, auto-approved actions without exclusions and inline secrets), `playbook-testing`, `automation-risk-review`, `automated-containment-guardrails`, `enrichment-automation`, `automation-metrics`.
- `security-testing` category (6 skills): `detection-validation` (tested; `coverage_matrix.py` scores an emulation run against exported alerts as detected / detected-other / missed with latency), `purple-team-exercise`, `control-validation`, `security-test-planning`, `attack-simulation-safety`, `bas-results-review`.
- `automation` and `purple` install profiles and plugins; `security-testing` added to the `detection` profile.
- Newly `tested` skills with scripts and fixtures: `zeek-log-analysis` (`zeek_triage.py`), `okta-log-investigation` (`okta_hunts.py`), `entra-signin-investigation` (`signin_review.py`), `osquery-investigation` (`osquery_diff.py`, plus the whole Linux query library run in an osquery 5.17 container against a planted scenario).
- `references/` files loaded on demand: Windows event IDs (`windows-event-log-analysis`), AADSTS result codes (`entra-signin-investigation`), ASVS 5.0 / OWASP Top 10:2025 / API Top 10 2023 / LLM Top 10 2025 mappings (`security-requirements`).
- Skill-trigger evals: `evals/cases.json` → generated `evals/*/case.yaml` (should-trigger and should-not-trigger per profile) and `claude_blue.py eval-plugin <profile> <dir>` to build a standalone plugin for `claude plugin eval`.
- `tools/check_links.py` and `tools/refresh_attack.py`, run weekly by the new non-blocking `maintenance.yml` workflow. CI also pulls the osquery image.
- 26 new tests (75 total).

### Changed
- Validator: reference files must be Markdown, cite a source and be named in SKILL.md; eval cases must name existing skills in the case's profile and use JavaScript-compatible regexes; generated eval files must be current.

### Fixed
- The installer copied and hashed `__pycache__`/`.pyc` files, so running a bundled script could make an installed skill look locally modified and block upgrade/uninstall. Bytecode caches are now neither shipped nor hashed.
- Found by the new tests and checks: Docker mounts `/dev/shm` `noexec` and osquery's systemd tables print D-Bus warnings in containers (the test now mounts an exec tmpfs and treats only a non-zero exit as failure); `ipaddress.is_global` treats documentation ranges as private, so `zeek_triage.py` now uses explicit RFC 1918/6598 ranges; three dead or wrong reference URLs in the new skills.
- Evals: a `tool_used` grader with only `max: 0` defaults `min` to 1, so negative cases set `min: 0`; grader regexes are JavaScript (`flags: i`, no `(?i)`).

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
