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
| `pcap-analysis` | tshark conversation, DNS, HTTP, object export commands and JA3/JA4 field names (TShark 4.7) |

## Documentation-only integrations

All other commands and queries were written against current vendor documentation and are **not executed here**. That covers Splunk SPL, Sentinel/Defender KQL, Elastic EQL/ES|QL, AWS/Azure/GCP CLIs, Microsoft Graph and Exchange PowerShell, Okta/Google/GitHub APIs, Volatility, Velociraptor, osquery, Zeek, Suricata, Falco, Kubernetes tooling, scanners and SaaS consoles. Field names and table schemas vary by product version and deployment. Test a query on a small time range before relying on it. Each skill names the official documentation to confirm against.

## Not supported

- No live connectors to SIEM, EDR, cloud or SaaS APIs. No credential handling.
- No MCP server. Skills assume the operator or Claude uses whatever access the session already has.
- `security-automation` and `security-testing` categories are not yet included (see ROADMAP).
