# Handoff

## State
274 skills in 52 categories under `skills/<category>/<skill>/`, generated catalog and plugin marketplace, and a stdlib tool (`tools/claude_blue.py`). Tests: `python3 -m unittest discover -s tests -v`. Everything passes. Status details are in BUILD_STATUS.md.

## How to change things
- **Edit or add a skill**: follow an existing SKILL.md layout. Then run `python3 tools/claude_blue.py catalog && python3 tools/claude_blue.py validate`. The validator enforces portable frontmatter, "Use when" descriptions, Related skills/References sections, existing cross-references, valid ATT&CK v20 IDs and no repeated boilerplate.
- **Mark a skill `tested`** only when a bundled script or a test in `tests/` exercises it.
- **Profiles/plugins**: edit `tools/profiles.json`, then run `catalog`; it regenerates `.claude-plugin/marketplace.json`.
- **ATT&CK refresh**: `python3 tools/refresh_attack.py` rebuilds `tools/data/attack-enterprise.json` from MITRE attack-stix-data (`--check` only reports). Then run `validate` and fix the IDs it flags.
- **Reference files**: put long lookup tables in `skills/<cat>/<skill>/references/<topic>.md` and link them from SKILL.md with a sentence saying when to read them.
- **Evals**: edit `evals/cases.json`, run `catalog`, then `python3 tools/claude_blue.py eval-plugin <profile> /tmp/x && claude plugin eval /tmp/x --no-publish`.

## Decisions to know
- Plugin names use the `blue-team-` prefix because Claude Code rejects names starting with `claude-`.
- Installer manifest name `.claude-blue-manifest.json` deliberately avoids `manifest.json`. Claude Code before 2.1.280 treated that name specially in `~/.claude/skills`.
- No root plugin.json. Marketplace entries (`strict: false`, `source: "./"`) are the manifests, so each profile plugin loads only its categories.

## Open items
1. Execute documented KQL in the Kusto emulator (Kustainer, multi-GB image) and SPL in a Splunk container, then promote those skills to `tested` (ROADMAP).
2. Widen evals beyond the smoke cases: more prompts per profile and full 3-run passes; record pass rates in BUILD_STATUS.
3. Repository: https://github.com/kaandgnsh/Claude-Blue
