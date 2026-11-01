# Claude-Blue

<p align="center">
  <strong>A defensive cybersecurity skill library for Claude Code: 274 task-specific skills for SOC, DFIR, detection engineering, security engineering, security automation and testing, cloud, identity, AppSec, GRC, OT and AI security.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Skills-274-1F6FEB?style=for-the-badge" alt="274 skills">
  <img src="https://img.shields.io/badge/Categories-52-444444?style=for-the-badge" alt="52 categories">
  <img src="https://img.shields.io/badge/Claude%20Code-Plugin%20%2B%20Skills-D97757?style=for-the-badge" alt="Claude Code plugin and skills">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/License-MIT-315C45?style=for-the-badge" alt="MIT license">
  <a href="https://hub.xerj.org/corpus/kaandgnsh--claude-blue">
    <img src="https://img.shields.io/badge/Listed%20on-XERJ%20Corpus%20Hub-6E40C9?style=for-the-badge" alt="Listed on XERJ Corpus Hub">
  </a>
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

Claude-Blue is listed as a reference corpus on [XERJ Corpus Hub](https://hub.xerj.org/corpus/kaandgnsh--claude-blue), the AI-agent corpus catalog from [xerj-org/xerj](https://github.com/xerj-org/xerj) (⭐18k+).

Skills are written in the [Agent Skills](https://agentskills.io/specification) format. Claude Code loads one automatically when your request matches its description, or you invoke it by name.

> [!WARNING]
> **Defensive use only.** These workflows are for systems and data you are authorized to protect. Skills put read-only investigation first, and require approval, rollback and verification for disruptive actions such as isolation, account disablement or credential rotation. They do not replace your incident command, legal counsel or vendor documentation. Field names and schemas vary by product version, so test any query on a small time range first.

## Features

- **274 independent skills in 52 categories**, each with its own scope and procedure. A validator rejects repeated boilerplate.
- **Builds controls, not just reviews.** The `security-engineering` category produces deployable blue-team artifacts:
  - an nftables host firewall generated from a policy and tested with real traffic in isolated network namespaces, with an auto-rollback apply that prevents lockout;
  - a hardened SSH configuration with post-quantum KEX, live-tested against weak clients;
  - a secure scaffold for blue-team tools;
  - cloud firewalls as code, a TLS reverse proxy, IDS deployment, log shipping and Ansible hardening automation.
- **Tested where it counts.** 22 skills are marked `tested`. Their bundled standard-library scripts, their embedded Sigma, YARA and tshark examples, and the osquery query library (run inside an osquery container against a planted scenario) execute in CI. The rest are clearly labelled `documented`.
- **Automation and testing.** `security-automation` designs, lints, tests and measures SOAR playbooks and automatic containment guardrails; `security-testing` plans purple-team exercises and security tests, runs emulation safely, validates controls and scores detection coverage from exported alerts.
- **Bundled scripts:** timeline merging, beacon scoring, `.eml` header analysis, IOC extraction, GitHub Actions auditing, Kubernetes RBAC auditing, CloudTrail summarizing, IAM policy linting, password-spray detection, Zeek log triage, Okta System Log hunts, Entra ID sign-in review, osquery baseline diffs, SOAR playbook linting and emulation coverage scoring.
- **Current frameworks.** ATT&CK IDs are validated against ATT&CK **v20**. Skills also align with NIST SP 800-61r3, CSF 2.0, OWASP ASVS 5.0, the OWASP API Top 10 (2023) and the OWASP LLM Top 10 (2025).
- **Role-based profiles** (`soc`, `dfir`, `detection`, `cloud`, `identity`, `appsec`, `grc`, `ot`, `ai`, `automation`, `purple`, …) keep installs within Claude Code's skill-listing context budget.
- **Native Claude Code plugins.** The repository is a plugin marketplace with one plugin per profile.
- **Trigger evals.** `evals/` holds should-trigger and should-not-trigger cases per profile for `claude plugin eval`, generated from one `evals/cases.json`.
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
| **Security engineering** | `security-engineering` (firewall, SSH, TLS proxy, IDS, log shipping, hardening automation, cloud firewall, tool development) |
| **Automation & testing** | `security-automation` (SOAR playbook design and testing, containment guardrails, enrichment, automation risk and metrics) · `security-testing` (purple team, detection validation, control validation, test planning, simulation safety, BAS review) |
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
/plugin install blue-team-engineering --marketplace kaandgnsh/Claude-Blue
/plugin install blue-team-automation --marketplace kaandgnsh/Claude-Blue
/plugin install blue-team-purple --marketplace kaandgnsh/Claude-Blue
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
> Prefer a profile over `--all`. Claude Code always lists skill names, but it drops descriptions once the listing exceeds its context budget. 274 descriptions exceed that budget, which makes automatic triggering less reliable. See [docs/INSTALL.md](docs/INSTALL.md) for details.

## Usage

Ask in plain language and the matching skill loads automatically:

```text
> Triage this Defender alert for rundll32 spawning from WINWORD.EXE on FIN-WS-042
> Is this email spoofed? (attach the .eml)
> We found an AWS access key in a public repo, walk me through containment and scoping
> Review .github/workflows for pwn-request and script-injection issues
> Build an nftables firewall for this web server: SSH only from 10.20.0.0/24, HTTPS for everyone
> Harden sshd on our fleet and give me an Ansible role to roll it out
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
| Catalog validator (`tools/claude_blue.py validate`) | 0 errors across 274 skills |
| Unit tests (`python3 -m unittest discover -s tests`) | 75 passing (3 skipped locally without YARA/Sigma; CI installs them) |
| osquery query library | Every Linux query runs in osquery 5.17 and finds the planted implant, `/dev/shm` process, SSH key, cron entry and web shell |
| Cited URLs (`tools/check_links.py`) | 757 checked, 0 broken (59 refuse automated clients) |
| Skill-trigger evals (`claude plugin eval`) | Expected skill fired in the soc, automation and purple smoke runs |
| Generated firewall (real traffic in network namespaces) | Every probe matches the policy; an overly permissive ruleset is caught |
| Generated sshd config (live server) | Key login works; passwords, CBC, SHA-1 KEX/MAC and forwarding refused |
| Embedded Sigma rules | `sigma check` with 0 errors and 0 issues; converts to Splunk SPL |
| Embedded YARA rules | Compile with YARA 4 |
| `claude plugin validate .` | Passes |
| Installed skills (`claude plugin validate ~/.claude/skills`) | All pass |

The validator checks for:

- portable frontmatter;
- "Use when" trigger descriptions;
- existing related skills, links and scripts;
- valid ATT&CK v20 technique IDs;
- `references/` files that SKILL.md actually points to;
- eval cases that name existing skills inside the right profile;
- size limits;
- copy-pasted boilerplate;
- a stale catalog.

[TOOLS.md](TOOLS.md) separates **tested** integrations from **documentation-only** ones. [docs/QUALITY.md](docs/QUALITY.md) explains every gate.

## Development

```bash
python3 tools/claude_blue.py validate        # quality gates
python3 tools/claude_blue.py catalog         # regenerate catalog.json, CATALOG.md, the marketplace and evals/
python3 -m unittest discover -s tests -v     # tests (optional tools are skipped with a reason)
claude plugin validate .                     # Claude Code's own validation
python3 tools/check_links.py                 # check cited URLs (network)
python3 tools/refresh_attack.py --check      # is the ATT&CK snapshot current? (network)
```

Skill-trigger evals run per profile against a standalone plugin build:

```bash
python3 tools/claude_blue.py eval-plugin soc /tmp/blue-team-soc
claude plugin eval /tmp/blue-team-soc --no-publish --runs 1 --max-cost-usd 2
```

Add cases to `evals/cases.json` (skill, profile, prompt, a regex the answer should match, and optional equally-correct `also` skills), then run `catalog`.

To add a skill, create `skills/<category>/<skill-name>/SKILL.md` following an existing one, then run `catalog` and `validate`. Mark it `tested` only when a bundled script or a test exercises it.

## Project layout

```text
skills/<category>/<skill>/SKILL.md     one task per skill
skills/<category>/<skill>/scripts/     optional stdlib helper scripts
skills/<category>/<skill>/references/  optional detail loaded on demand (event IDs, error codes, mappings)
evals/cases.json                       skill-trigger eval source; evals/*/case.yaml are generated
tools/claude_blue.py                   validate · catalog · eval-plugin · list · install · uninstall
tools/check_links.py                   URL checker · tools/refresh_attack.py ATT&CK snapshot refresh
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
