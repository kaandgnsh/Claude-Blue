# Build status

Updated: 2026-10-31 (v2.1.0)

| Item | Status |
|---|---|
| Skills / categories | **262 / 50** (0 template skills remain) |
| Verification labels | 16 `tested`, 246 `documented` |
| Bundled scripts | 16 files (Python stdlib + bash), all covered by tests |
| `tools/claude_blue.py validate` | Pass: 0 errors |
| Unit tests | **49 run, 49 pass, 0 skipped** (with yara-python 4, sigma-cli 4.0 + Splunk backend, TShark 4.7, nftables 1.1.7, OpenSSH 10.6 installed) |
| Embedded detection content | 4 Sigma rules: `sigma check` 0 errors / 0 issues, Splunk conversion OK. 1 YARA rule compiles |
| `claude plugin validate .` | Pass (Claude Code 2.1.314) |
| `claude plugin validate` on installed skills | Pass |
| Live discovery (`claude -p` in project with SOC skills) | Expected skills listed |
| Reference URLs | 687 checked; broken ones fixed; some sites block automated clients (403/timeouts) |

## Not done
- `security-automation` and `security-testing` categories (not yet included; see ROADMAP).
- Vendor queries (KQL/SPL/EQL, cloud CLIs, PowerShell) are documentation-based and were not executed against live products.
- No live SIEM/EDR/cloud connectors (by design; see TOOLS.md).
