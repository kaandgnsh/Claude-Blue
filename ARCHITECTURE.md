# Architecture

```
skills/<category>/<skill>/SKILL.md      one task per skill (Agent Skills format)
skills/<category>/<skill>/scripts/      optional stdlib Python / bash helper scripts (12 skills)
tools/claude_blue.py                    validate · catalog · list · install · uninstall · extract-rules
tools/profiles.json                     role-based install profiles (category groups)
tools/data/attack-enterprise.json       ATT&CK Enterprise v20 snapshot used to validate technique IDs
catalog.json, CATALOG.md                generated index (do not edit)
.claude-plugin/marketplace.json         generated: one Claude Code plugin per profile + "all"
tests/                                  unittest suite + fixtures
```

## Design decisions

- **Category-nested source, flat install.** Claude Code discovers `<skills-dir>/<name>/SKILL.md` one level deep. The installer flattens categories. The plugin marketplace points each plugin's `skills` array at category directories, which Claude Code scans for `<name>/SKILL.md`.
- **Profiles instead of one giant install.** Claude Code's skill listing has a context budget (about 1% of the context window). With 253 skills, descriptions would be dropped and triggering would degrade. Profiles keep each install to 23–49 skills.
- **Plugin naming.** `claude plugin validate` rejects plugin names starting with `claude-`, so plugins are named `blue-team-<profile>`.
- **Portable frontmatter.** Only keys accepted by claude.ai and the Skills API are used. Claude Code-only keys (`allowed-tools` excepted) would break uploads elsewhere.
- **Progressive disclosure.** SKILL.md bodies are kept under 500 lines (largest is 98 lines). Scripts are executed rather than loaded into context, and referenced as `scripts/<file>` relative to the skill directory.
- **Verification labels.** `metadata.verification: tested|documented` tells users which content was executed in this repository.
- **ATT&CK currency.** IDs are validated against ATT&CK v20. That release split Defense Evasion into the *Stealth* and *Defense Impairment* tactics and replaced T1562 with T1685/T1686.
