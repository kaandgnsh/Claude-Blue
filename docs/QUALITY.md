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

## Test suite (`python3 -m unittest discover -s tests -v`)

- `test_scripts.py` runs all 9 bundled scripts against fixtures in `tests/fixtures/`.
- `test_examples.py`:
  - compiles the embedded YARA rules (yara-python);
  - runs `sigma check` (0 errors and 0 issues required) and `sigma convert -t splunk` on every embedded Sigma rule;
  - runs the `pcap-analysis` tshark commands against `tests/fixtures/http_dns.pcap`.
  These tests are skipped with a reason when the optional tool is not installed. CI installs all of them.
- `test_tooling.py` covers the validator, frontmatter parser and installer/uninstaller safety.

## External checks run for v2.0.0 (not in CI)

- `claude plugin validate .` (Claude Code 2.1.314) on the marketplace passed. `claude plugin validate <dir>` on all 253 installed SKILL.md files also passed.
- A headless `claude -p` session in a project with the SOC skills installed listed the expected skills (discovery check).
- Reference URL check: all 687 unique reference URLs were fetched. Every broken link was fixed. Placeholder URLs in examples are expected not to resolve. Some government and vendor sites return 403/timeouts to automated clients and were left in place.

## What the gates cannot prove

They do not prove that a query runs on your SIEM schema, that a detection is effective in your environment, or that guidance is complete for your regulatory context. Skills marked `documented` contain commands and queries written from vendor documentation and were not executed here.
