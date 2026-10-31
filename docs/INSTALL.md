# Installation and removal

Requirements: Python 3.10+ (standard library only) for the installer. Claude Code for using the skills.

## Option A — Claude Code plugin (recommended)

The repository is a plugin marketplace (`.claude-plugin/marketplace.json`). Each install profile is a separate plugin, so you load only the skills you need:

```text
/plugin marketplace add kaandgnsh/Claude-Blue          # or a local path: /plugin marketplace add ./Claude-Blue
/plugin install blue-team-soc@claude-blue-marketplace
```

Plugins: `blue-team-ai`, `blue-team-appsec`, `blue-team-cloud`, `blue-team-detection`, `blue-team-dfir`, `blue-team-engineering`, `blue-team-grc`, `blue-team-hunting`, `blue-team-identity`, `blue-team-ot`, `blue-team-platform`, `blue-team-soc`, `blue-team-all`. Plugin skills are namespaced, e.g. `/blue-team-soc:alert-triage`. (Plugin names cannot start with `claude-`; Claude Code reserves that prefix.)

## Option B — copy skills with the installer

```sh
python3 tools/claude_blue.py list --profiles
python3 tools/claude_blue.py install --profile soc --dry-run
python3 tools/claude_blue.py install --profile soc                         # user scope: ~/.claude/skills
python3 tools/claude_blue.py install --scope project --project-dir . --category dfir   # project scope: ./.claude/skills
python3 tools/claude_blue.py install --skill alert-triage --skill phishing-triage
python3 tools/claude_blue.py install --profile soc --upgrade               # update unmodified installed skills
python3 tools/claude_blue.py uninstall --category dfir                     # partial removal
python3 tools/claude_blue.py uninstall                                     # remove everything it installed
```

Safety properties (all covered by `tests/test_tooling.py`):

- An explicit selection is required (`--profile`, `--category`, `--skill` or `--all`).
- Never overwrites a skill directory it did not install. Collisions abort before anything is copied.
- Records ownership and SHA-256 hashes in `.claude-blue-manifest.json` in the target directory. That file name is distinct from the `manifest.json` name that older Claude Code versions treated specially.
- Copies each skill into a staging directory, verifies the hashes, then renames it into place. The manifest is updated after every skill, so an interrupted install stays tracked.
- `--upgrade` replaces only skills whose files still match the recorded hashes. Locally edited skills are reported and left untouched.
- Uninstall removes only unmodified skills it owns and keeps edited ones. It refuses manifests with unsafe paths and never follows symlinked skill directories.
- Refuses to run as root unless `--allow-root` is passed. Skills are per-user files, so root is never needed.
- `--dry-run` writes nothing (it does not even create the target directory).

## Context budget

Claude Code always lists skill names, but it drops descriptions once the listing exceeds its budget (about 1% of the context window). Install a role profile rather than all 262 skills at user level. Alternatively, raise `skillListingBudgetFraction` or use `skillOverrides` to list low-priority skills name-only.
