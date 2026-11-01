# Quality gates

## `python3 tools/claude_blue.py validate`

Per skill:
- Frontmatter: strict YAML subset parser. Rejects tabs, duplicate keys and complex values. Only portable keys are allowed (`name`, `description`, `license`, `compatibility`, `metadata`, `allowed-tools`), so skills also load in claude.ai and the Skills API.
- Name: kebab-case, ≤ 64 characters, equal to the directory name, unique, and free of the reserved words `claude`/`anthropic`.
- Description: ≤ 1024 characters, includes "Use when…" trigger text, no angle brackets.
- `metadata.category` matches the directory; `metadata.version` is semver; `metadata.verification` is `documented` or `tested`.
- `tested` requires a bundled script or a test in `tests/` that names the skill.
- Body: H1 present, ≥ 1800 characters, ≤ 500 lines, plus `## Related skills` and `## References` sections (the latter with URLs).
- Every related skill exists; relative links and referenced `scripts/…` files exist.
- Every ATT&CK technique ID exists in the bundled ATT&CK Enterprise v20 snapshot (`tools/data/attack-enterprise.json`, taken from MITRE's attack-stix-data via pySigma). Sigma `attack.<tactic>` tags must be v20 tactics.

Repository-wide:
- No symlinks in `skills/`; every skill directory has a SKILL.md.
- **Boilerplate detector**: any prose line of 60 or more characters that appears in more than 8 skills fails validation. This prevents a return to the template-generated content found in the v1 catalog.
- Install profiles reference existing categories.
- `catalog.json`, `CATALOG.md` and `.claude-plugin/marketplace.json` match the generated output.
- Every file in a skill's `references/` is Markdown, cites a source URL and is named in SKILL.md (otherwise Claude never opens it).
- `evals/cases.json` names existing skills inside the case's profile, uses JavaScript-compatible regexes, and `evals/*/case.yaml` match the generated output.

## Test suite (`python3 -m unittest discover -s tests -v`)

- `test_scripts.py` runs the analysis scripts against fixtures in `tests/fixtures/`.
- `test_engineering.py` tests the builder skills:
  - generated nftables rulesets run under real traffic in isolated network namespaces, including a negative control;
  - every `safe_apply.sh` path;
  - generated sshd configs against a live sshd, with a weak config that must fail;
  - the tool scaffold's own tests and CI.
  These tests are skipped with a reason if unprivileged namespaces, nft or OpenSSH are unavailable.
- `test_examples.py`:
  - compiles the embedded YARA rules (yara-python);
  - runs `sigma check` (0 errors and 0 issues required) and `sigma convert -t splunk` on every embedded Sigma rule;
  - runs the `pcap-analysis` tshark commands against `tests/fixtures/http_dns.pcap`.
  These tests are skipped with a reason when the optional tool is not installed. CI installs all of them.
- `test_tooling.py` covers the validator, frontmatter parser, installer/uninstaller safety (bytecode caches are neither shipped nor treated as local edits), the ATT&CK refresh builder and the link checker (against a local HTTP server).
- `test_osquery.py` plants a scenario in an osquery 5.17 container and runs every Linux query of `osquery-investigation`; skipped when Docker or the image is missing (CI pulls it).

## External checks run for v2.0.0 (not in CI)

- `claude plugin validate .` (Claude Code 2.1.314) on the marketplace passed. `claude plugin validate <dir>` on all installed SKILL.md files also passed.
- A headless `claude -p` session in a project with the SOC skills installed listed the expected skills (discovery check).
- Reference URL check: all 687 unique reference URLs were fetched. Every broken link was fixed. Placeholder URLs in examples are expected not to resolve. Some government and vendor sites return 403/timeouts to automated clients and were left in place.

## Checks added in v2.2.0

- `tools/check_links.py`: 757 cited URLs, 0 broken; 59 return 403/429/5xx or time out for automated clients and are listed as `blocked`. Runs weekly in `maintenance.yml` (non-blocking).
- `tools/refresh_attack.py --check`: the bundled snapshot equals MITRE attack-stix-data Enterprise v20 as of 2026-11-01. Runs weekly; a new ATT&CK release shows up as a warning plus the `validate` errors it causes.
- Skill-trigger smoke evals (`claude plugin eval`, 1-3 runs per case) for the soc, automation and purple profiles: the expected skill fired in every run. Purple-team prompts are sometimes stopped by the model's cyber safeguards before the answer finishes (Opus and Sonnet); the plan is defensive, so this is reported, not "fixed" by weakening the skill.

## What the gates cannot prove

They do not prove that a query runs on your SIEM schema, that a detection is effective in your environment, or that guidance is complete for your regulatory context. Skills marked `documented` contain commands and queries written from vendor documentation and were not executed here.
