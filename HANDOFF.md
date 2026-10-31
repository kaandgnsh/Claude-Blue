# Handoff

## State
253 skills in 49 categories under `skills/<category>/<skill>/`, generated catalog and plugin marketplace, and a stdlib tool (`tools/claude_blue.py`). Tests: `python3 -m unittest discover -s tests -v`. Everything passes. Status details are in BUILD_STATUS.md.

## How to change things
- **Edit or add a skill**: follow an existing SKILL.md layout. Then run `python3 tools/claude_blue.py catalog && python3 tools/claude_blue.py validate`. The validator enforces portable frontmatter, "Use when" descriptions, Related skills/References sections, existing cross-references, valid ATT&CK v20 IDs and no repeated boilerplate.
- **Mark a skill `tested`** only when a bundled script or a test in `tests/` exercises it.
- **Profiles/plugins**: edit `tools/profiles.json`, then run `catalog`; it regenerates `.claude-plugin/marketplace.json`.
- **ATT&CK refresh**: regenerate `tools/data/attack-enterprise.json` from MITRE attack-stix-data. The current snapshot was extracted via `sigma.data.mitre_attack` in pySigma.

## Decisions to know
- Plugin names use the `blue-team-` prefix because Claude Code rejects names starting with `claude-`.
- Installer manifest name `.claude-blue-manifest.json` deliberately avoids `manifest.json`. Claude Code before 2.1.280 treated that name specially in `~/.claude/skills`.
- No root plugin.json. Marketplace entries (`strict: false`, `source: "./"`) are the manifests, so each profile plugin loads only its categories.

## Open items
1. Write the `security-automation` and `security-testing` categories (ROADMAP).
2. Repository: https://github.com/kaandgnsh/Claude-Blue
3. Optional: execute documented KQL/SPL against test tenants or containers and promote skills to `tested`.
