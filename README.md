# Claude-Blue

<p align="center">
  <strong>A defensive cybersecurity skill library for Claude Code: 253 task-specific skills for SOC, DFIR, detection engineering, cloud, identity, AppSec, GRC, OT and AI security.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Skills-253-1F6FEB?style=for-the-badge" alt="253 skills">
  <img src="https://img.shields.io/badge/Categories-49-444444?style=for-the-badge" alt="49 categories">
  <img src="https://img.shields.io/badge/Claude%20Code-Plugin%20%2B%20Skills-D97757?style=for-the-badge" alt="Claude Code plugin and skills">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/License-MIT-315C45?style=for-the-badge" alt="MIT license">
  <a href="https://github.com/kaandgnsh/Claude-Blue/actions/workflows/quality.yml">
    <img src="https://github.com/kaandgnsh/Claude-Blue/actions/workflows/quality.yml/badge.svg?branch=main" alt="Quality">
  </a>
</p>

<p align="center">
  <a href="#overview">Overview</a> ·
  <a href="#features">Features</a> ·
  <a href="#coverage">Coverage</a> ·
  <a href="#installation">Installation</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#verification">Verification</a> ·
  <a href="#development">Development</a> ·
  <a href="#project-layout">Layout</a> ·
  <a href="#acknowledgements">Acknowledgements</a>
</p>

---

## Overview

**Claude-Blue** turns Claude Code into a blue-team assistant. Every skill is a focused, working procedure for one defensive task, such as triaging an EDR alert, scoping a leaked AWS key, detecting Kerberoasting or reviewing a GitHub Actions workflow. Each includes:

- concrete commands and queries (KQL, SPL, EQL/ES|QL, jq, PowerShell, cloud CLIs);
- detection logic and interpretation guidance;
- output templates you can paste into a case;
- explicit safety boundaries;
- links to related skills and official references.

Skills are written in the [Agent Skills](https://agentskills.io/specification) format. Claude Code loads one automatically when your request matches its description, or you invoke it by name.

> [!WARNING]
> **Defensive use only.** These workflows are for systems and data you are authorized to protect. Skills put read-only investigation first, and require approval, rollback and verification for disruptive actions such as isolation, account disablement or credential rotation. They do not replace your incident command, legal counsel or vendor documentation. Field names and schemas vary by product version, so test any query on a small time range first.

## Features

- **253 independent skills in 49 categories**, each with its own scope and procedure. A validator rejects repeated boilerplate.
- **Tested where it counts.** 13 skills are marked `tested`. Their 9 bundled standard-library scripts and their embedded Sigma, YARA and tshark examples run in CI. The rest are clearly labelled `documented`.
- **Bundled scripts:** timeline merging, beacon scoring, `.eml` header analysis, IOC extraction, GitHub Actions auditing, Kubernetes RBAC auditing, CloudTrail summarizing, IAM policy linting and password-spray detection.
- **Current frameworks.** ATT&CK IDs are validated against ATT&CK **v20**. Skills also align with NIST SP 800-61r3, CSF 2.0, OWASP ASVS 5.0, the OWASP API Top 10 (2023) and the OWASP LLM Top 10 (2025).
- **Role-based profiles** (`soc`, `dfir`, `detection`, `cloud`, `identity`, `appsec`, `grc`, `ot`, `ai`, …) keep installs within Claude Code's skill-listing context budget.
- **Native Claude Code plugins.** The repository is a plugin marketplace with one plugin per profile.
- **Safe installer:**
  - never overwrites skills it didn't install;
  - verifies copies with SHA-256;
  - upgrades only unmodified skills;
  - removes only what it owns;
  - refuses to run as root.
- **No dependencies, no telemetry, no credentials.** The tooling is Python standard library only.

## Coverage

| Area | Categories |
|---|---|
| **Operations** | `soc-operations` · `incident-response` · `edr-operations` · `threat-hunting` · `threat-intelligence` · `deception` · `insider-risk` |
| **Forensics & malware** | `dfir` · `malware-analysis` · `windows-security` · `linux-security` · `endpoint-security` · `mobile-security` |
| **Detection & SIEM** | `detection-engineering` · `siem-engineering` · `network-security` · `email-security` · `wireless-security` |
| **Identity** | `identity-security` · `identity-governance` · `active-directory-security` |
| **Cloud & platform** | `cloud-security` · `aws-security` · `azure-security` · `gcp-security` · `saas-security` · `kubernetes-security` · `container-security` |
| **Application & supply chain** | `appsec` · `api-security` · `devsecops` · `supply-chain-security` · `secrets-management` · `web-application-defense` |
| **Data & privacy** | `data-security` · `privacy-engineering` · `database-security` |
| **Risk & resilience** | `security-governance` · `compliance-audit` · `third-party-risk` · `security-metrics` · `business-continuity` · `security-architecture` · `asset-attack-surface` · `vulnerability-management` · `security-research` · `security-awareness` |
| **Specialized** | `ai-security` · `ot-ics-security` |

The full index with every skill and its description is in **[CATALOG.md](CATALOG.md)**.

## Requirements

- [Claude Code](https://code.claude.com/docs) (plugin install: 2.1.275 or newer recommended)
- Python 3.10 or newer, for the installer and bundled scripts
- Optional, for the full test suite: `yara-python`, `sigma-cli`, `pysigma-backend-splunk`, `tshark`

## Installation

### Option 1 — Claude Code plugin (recommended)

Add the marketplace, then install the profile you need:

```text
/plugin marketplace add kaandgnsh/Claude-Blue
/plugin install blue-team-soc@claude-blue-marketplace
```

One-step install lines for each plugin:

```text
/plugin install blue-team-soc --marketplace kaandgnsh/Claude-Blue
/plugin install blue-team-dfir --marketplace kaandgnsh/Claude-Blue
/plugin install blue-team-detection --marketplace kaandgnsh/Claude-Blue
/plugin install blue-team-hunting --marketplace kaandgnsh/Claude-Blue
/plugin install blue-team-cloud --marketplace kaandgnsh/Claude-Blue
/plugin install blue-team-identity --marketplace kaandgnsh/Claude-Blue
/plugin install blue-team-appsec --marketplace kaandgnsh/Claude-Blue
/plugin install blue-team-platform --marketplace kaandgnsh/Claude-Blue
/plugin install blue-team-grc --marketplace kaandgnsh/Claude-Blue
/plugin install blue-team-ot --marketplace kaandgnsh/Claude-Blue
/plugin install blue-team-ai --marketplace kaandgnsh/Claude-Blue
/plugin install blue-team-all --marketplace kaandgnsh/Claude-Blue
```

### Option 2 — skill folders with the installer

```bash
git clone https://github.com/kaandgnsh/Claude-Blue.git
cd Claude-Blue

python3 tools/claude_blue.py list --profiles                        # see profiles and sizes
python3 tools/claude_blue.py install --profile soc --dry-run        # preview
python3 tools/claude_blue.py install --profile soc                  # user scope: ~/.claude/skills
python3 tools/claude_blue.py install --scope project --profile cloud   # project scope: ./.claude/skills
python3 tools/claude_blue.py install --profile soc --upgrade        # update unmodified installs
python3 tools/claude_blue.py uninstall                              # remove only what it installed
```

> [!TIP]
> Prefer a profile over `--all`. Claude Code always lists skill names, but it drops descriptions once the listing exceeds its context budget. 253 descriptions exceed that budget, which makes automatic triggering less reliable. See [docs/INSTALL.md](docs/INSTALL.md) for details.

## Usage

Ask in plain language and the matching skill loads automatically:

```text
> Triage this Defender alert for rundll32 spawning from WINWORD.EXE on FIN-WS-042
> Is this email spoofed? (attach the .eml)
> We found an AWS access key in a public repo, walk me through containment and scoping
> Review .github/workflows for pwn-request and script-injection issues
> Build a Sigma rule for LSASS dumping via comsvcs.dll and convert it to Splunk
```

Or invoke a skill directly: `/alert-triage`, or `/blue-team-soc:alert-triage` when installed as a plugin.

Bundled scripts can also be run on their own:

```bash
python3 skills/email-security/email-header-analysis/scripts/parse_eml.py reported.eml
python3 skills/threat-intelligence/ioc-assessment/scripts/ioc_extract.py report.txt --defang
python3 skills/devsecops/github-actions-hardening/scripts/gha_audit.py .github/workflows
```

## Verification

| Check | Result |
|---|---|
| Catalog validator (`tools/claude_blue.py validate`) | 0 errors across 253 skills |
| Unit tests (`python3 -m unittest discover -s tests`) | 34 / 34 passing |
| Embedded Sigma rules | `sigma check` with 0 errors and 0 issues; converts to Splunk SPL |
| Embedded YARA rules | Compile with YARA 4 |
| `claude plugin validate .` | Passes |
| Installed skills (`claude plugin validate ~/.claude/skills`) | All 253 pass |

The validator checks for:

- portable frontmatter;
- "Use when" trigger descriptions;
- existing related skills, links and scripts;
- valid ATT&CK v20 technique IDs;
- size limits;
- copy-pasted boilerplate;
- a stale catalog.

[TOOLS.md](TOOLS.md) separates **tested** integrations from **documentation-only** ones. [docs/QUALITY.md](docs/QUALITY.md) explains every gate.

## Development

```bash
python3 tools/claude_blue.py validate        # quality gates
python3 tools/claude_blue.py catalog         # regenerate catalog.json, CATALOG.md and the marketplace
python3 -m unittest discover -s tests -v     # tests (optional tools are skipped with a reason)
claude plugin validate .                     # Claude Code's own validation
```

To add a skill, create `skills/<category>/<skill-name>/SKILL.md` following an existing one, then run `catalog` and `validate`. Mark it `tested` only when a bundled script or a test exercises it.

## Project layout

```text
skills/<category>/<skill>/SKILL.md     one task per skill
skills/<category>/<skill>/scripts/     optional stdlib helper scripts
tools/claude_blue.py                   validate · catalog · list · install · uninstall
tools/profiles.json                    role-based install profiles
tools/data/attack-enterprise.json      ATT&CK v20 snapshot for ID validation
.claude-plugin/marketplace.json        generated Claude Code plugin marketplace
tests/                                 unit tests and fixtures
```

More detail: [ARCHITECTURE.md](ARCHITECTURE.md) · [CHANGELOG.md](CHANGELOG.md) · [ROADMAP.md](ROADMAP.md)

## Acknowledgements

The idea for Claude-Blue came from **[Claude-Red](https://github.com/SnailSploit/Claude-Red)** by SnailSploit, a skill library for **red team** (offensive) work. Claude-Blue is a separate, independent project built for the **blue team**. It is not a fork or extension of Claude-Red, and it shares no code or content with it.

## License

Released under the [MIT License](LICENSE).
