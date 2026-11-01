# Tools and integrations

Claude-Blue skills are instructions plus a few bundled, standard-library-only scripts. They do not ship API connectors or credentials. When a skill shows vendor queries or CLI commands, the operator runs them with their own tooling and access.

## Tested in this repository (executed by the test suite)

| Skill | What is tested |
|---|---|
| `timeline-analysis` | `scripts/merge_timeline.py`: CSV/JSONL merge, ISO and epoch (s/ms) parsing, timezone assumption, windowing, bad-row reporting |
| `beaconing-hunt` | `scripts/beacon_score.py`: separates a jittered 60 s beacon from random traffic |
| `email-header-analysis` | `scripts/parse_eml.py`: auth results, Received hops, Reply-To/Return-Path mismatch, defanged URLs, attachment hashes |
| `ioc-assessment` | `scripts/ioc_extract.py`: refang/defang, hashes, CVEs, non-global IP separation, file-name filtering |
| `github-actions-hardening` | `scripts/gha_audit.py`: pwn-request checkout, script injection, unpinned actions, missing permissions; also run on this repo's CI |
| `k8s-rbac-review` | `scripts/rbac_audit.py`: cluster-admin, secrets read by `system:authenticated`, exec/rolebinding escalation |
| `cloudtrail-investigation` | `scripts/cloudtrail_summary.py`: Records files and `lookup-events` output, identity and high-risk event summary |
| `aws-iam-review` | `scripts/iam_policy_lint.py`: admin wildcard, PassRole escalation, service wildcards; Deny statements ignored |
| `password-spray-detection` | `scripts/spray_detect.py`: sliding-window spray detection, success-after-spray |
| `sigma-authoring`, `sigma-conversion` | All embedded Sigma rules pass `sigma check` with no issues and convert with the Splunk backend |
| `yara-authoring` | Embedded YARA rule compiles with YARA 4 (yara-python) |
| `host-firewall-build` | `scripts/nft_policy.py` policy validation (lockout refusal, unknown keys, exposed admin ports); `nft -c` syntax; `scripts/netns_test.py` real TCP/UDP traffic in isolated network namespaces, including a negative control; `scripts/safe_apply.sh` confirm, reject, killed-session rollback and invalid-file paths |
| `ssh-hardening-build` | `scripts/sshd_harden.py` validation and `sshd -t`; `scripts/live_test.sh` against a live unprivileged sshd: key login works, only publickey offered, weak cipher/KEX/MAC and forwarding refused; a weak config fails |
| `security-tool-development` | `scripts/new_tool.py` scaffold: generated project's own tests pass, its CI passes `gha_audit.py`, overwrite and bad names refused |
| `pcap-analysis` | tshark conversation, DNS, HTTP, object export commands and JA3/JA4 field names (TShark 4.7) |
| `zeek-log-analysis` | `scripts/zeek_triage.py`: TSV and JSON logs (and .gz), long connections, external uploads, S0/REJ scanning, DNS tunnelling labels, rare user agents, invalid certs, executable transfers, svcctl service creation, DRSUAPI replication from non-DCs |
| `okta-log-investigation` | `scripts/okta_hunts.py`: factor reset then new-IP sign-in, push fatigue, session reuse across ASNs, IdP changes, human API tokens, admin grants; JSON array and JSON lines |
| `entra-signin-investigation` | `scripts/signin_review.py`: Graph and Log Analytics exports, impossible travel, spray then success, MFA denial bursts, legacy auth, scripted clients, session reuse across countries |
| `osquery-investigation` | Every Linux query of the skill runs in osquery 5.17 (Docker) against a planted deleted-binary implant, `/dev/shm` process, SSH key, cron entry and web shell; `scripts/osquery_diff.py` baseline diffs for osqueryi output and Fleet result logs |
| `soar-playbook-design` | `scripts/playbook_lint.py`: dangling/unreachable steps, non-terminating paths, unbounded loops, decisions without default, disruptive actions without approval/rollback/idempotency, inline secrets |
| `detection-validation` | `scripts/coverage_matrix.py`: detected / detected-other / missed per emulation step, host normalization, epoch and ISO times, latency median, `--fail-under` |

## Documentation-only integrations

All other commands and queries were written against current vendor documentation and are **not executed here**. That covers Splunk SPL, Sentinel/Defender KQL, Elastic EQL/ES|QL, AWS/Azure/GCP CLIs, Microsoft Graph and Exchange PowerShell, Okta/Google/GitHub APIs (the Okta and Entra *export analysis* scripts above are tested; live API calls are not), Volatility, Velociraptor, osquery on Windows and macOS, Zeek itself, Suricata, Falco, Kubernetes tooling, scanners and SaaS consoles. Field names and table schemas vary by product version and deployment. Test a query on a small time range before relying on it. Each skill names the official documentation to confirm against.

## Not supported

- No live connectors to SIEM, EDR, cloud or SaaS APIs. No credential handling.
- No MCP server. Skills assume the operator or Claude uses whatever access the session already has.
- `cloud-firewall-build`, `tls-reverse-proxy-build`, `ids-deployment-build`, `log-shipping-build` and `hardening-automation-build` are documentation-only: Terraform, nginx, Suricata, Vector/Fluent Bit and Ansible are not run by the test suite.
- `security-automation` and `security-testing` categories are not yet included (see ROADMAP).
