---
name: security-tool-development
description: Write defensive security tools and scripts (log parsers, IOC scanners, triage collectors, enrichment and automation utilities) to production quality — safe input handling, no shell injection, bounded resources, secret redaction, least privilege, tests, hardened CI and release hygiene — starting from a bundled tested project scaffold. Use when coding a blue-team tool, reviewing a security script before it runs on production systems, or turning an ad-hoc analysis script into a maintained tool.
license: MIT
metadata:
  category: security-engineering
  version: "2.1.0"
  verification: tested
---

# Security Tool Development

Defensive tools run on sensitive systems, often with elevated rights, against attacker-controlled input such as logs, emails, samples and PCAPs. Treat every input as hostile.

## Start from the scaffold

```sh
python3 scripts/new_tool.py log-sentry --dir ~/src --description "Scan logs for leaked credentials."
cd ~/src/log-sentry && PYTHONPATH=src python -m unittest discover -s tests -v
```
The scaffold refuses to overwrite an existing directory and generates:
- `cli.py`: argparse, clear exit codes (0 ok, 2 bad input), `--json` output, and logic kept as a pure function so it is testable;
- `safe.py` with four helpers:
  - `read_bounded` (regular files only, size cap);
  - `write_atomic` (temp file and rename, mode 0600);
  - `run` (argument lists only, no shell, timeout; rejects shell strings);
  - `redact` (masks tokens, passwords, AWS keys);
- unit tests, `pyproject.toml`, README, SECURITY.md;
- CI with SHA-pinned actions, `contents: read`, ruff, bandit and tests.

## Engineering rules

| Area | Rule |
|---|---|
| Input | Validate types, ranges and formats at the boundary; reject unknown fields; cap sizes, recursion depth and decompressed size (zip bombs); never `eval`/`pickle`/`yaml.load` untrusted data (`yaml.safe_load`, `json`) |
| Processes | `subprocess.run([...], shell=False, timeout=...)`; never build shell strings from input; resolve executables to absolute paths when running privileged |
| Files | Use `pathlib`, reject `..` and absolute paths from archives (Zip Slip), don't follow symlinks in untrusted trees, write atomically, restrictive permissions for outputs containing evidence |
| Network | TLS verification on, timeouts, allow-list destinations; for URL fetching from untrusted input, block private/metadata ranges (SSRF) |
| Secrets | From environment/secret store only; never logged — run output through `redact`; no secrets in argv (visible in `ps`) |
| Privilege | Run unprivileged by default; request elevation only for the specific step, and document why |
| Errors | Fail closed; distinct exit codes; no stack traces with sensitive data to end users |
| Output | Machine-readable (JSON/CSV) plus human summary; deterministic ordering for diffing; UTC ISO-8601 timestamps |
| Dependencies | Minimal; pinned with hashes for releases (`pip-compile --generate-hashes`); scanned (`sca-dependency-risk`) |
| Tests | Unit tests for parsing edge cases and malicious input (oversized, malformed, injection strings); fixtures with sanitized real data |
| Release | Signed tags/artifacts (`artifact-signing`), changelog, SECURITY.md |

## Review checklist for a security script before production

- [ ] Runs read-only unless the task requires changes, and supports `--dry-run` for changes.
- [ ] No `shell=True`, `os.system`, backticks, `eval`; every external call has a timeout.
- [ ] Handles hostile input without crashing or hanging (tests prove it).
- [ ] Does not exfiltrate data: no telemetry, and any external lookups are documented and optional.
- [ ] Logs actions with timestamps for the case record, without secrets.
- [ ] Bash: `set -euo pipefail`, `LC_ALL=C` for regex/ranges (locale-dependent `[a-z]` breaks in e.g. `tr_TR`), quoted variables, `shellcheck` clean.

## Related skills

`secure-build-workflow`, `secure-code-review`, `github-actions-hardening`, `sca-dependency-risk`

## References

- OWASP Secure Coding Practices: https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/
- Python subprocess security considerations: https://docs.python.org/3/library/subprocess.html#security-considerations
- Bandit: https://bandit.readthedocs.io/
- ShellCheck: https://www.shellcheck.net/
