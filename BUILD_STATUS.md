# Build status

Updated: 2026-11-01 (v2.2.0)

| Item | Status |
|---|---|
| Skills / categories | **274 / 52** (0 template skills remain) |
| Verification labels | 22 `tested`, 252 `documented` |
| Bundled scripts | 22 files (Python stdlib + bash), all covered by tests |
| `tools/claude_blue.py validate` | Pass: 0 errors |
| Unit tests | **75 run, 75 pass** locally with 3 skipped (YARA/Sigma not installed on this machine; CI installs them). osquery tests ran against osquery 5.17 in Docker |
| Embedded detection content | 4 Sigma rules: `sigma check` 0 errors / 0 issues, Splunk conversion OK. 1 YARA rule compiles |
| `claude plugin validate .` | Pass (Claude Code 2.1.314) |
| `claude plugin validate` on installed skills | Pass |
| Live discovery (`claude -p` in project with SOC skills) | Expected skills listed |
| Reference URLs | `tools/check_links.py`: 757 checked, 0 broken, 59 blocked for automated clients |
| ATT&CK snapshot | `tools/refresh_attack.py --check`: equal to upstream Enterprise v20 (2026-11-01) |
| Trigger evals | 17 cases. Smoke runs: soc 3/3 cases, automation 2/2, purple: expected skill fired in every run; some purple runs stopped by model cyber safeguards; LLM-judge scores vary between runs |

## Not done
- Vendor queries (KQL/SPL/EQL, cloud CLIs, PowerShell) are documentation-based and were not executed against live products or emulators (the Kustainer image download did not finish in this session).
- No live SIEM/EDR/cloud connectors (by design; see TOOLS.md).
