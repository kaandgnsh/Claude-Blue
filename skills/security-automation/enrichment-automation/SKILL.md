---
name: enrichment-automation
description: Build automated alert enrichment (asset/CMDB, identity, threat intelligence reputation, geolocation, prior cases, sandbox) with caching, rate-limit handling, data-sharing rules, normalized verdicts and write-back to the case. Use when designing enrichment for a SIEM or SOAR pipeline, when analysts repeat the same lookups on every alert, or when enrichment leaks data to third parties or hits API quotas.
license: MIT
metadata:
  category: security-automation
  version: "2.2.0"
  verification: documented
---

# Enrichment Automation

Enrichment is the safest and highest-return automation: it takes no action, yet removes the first 5-15 minutes of every triage. Done badly, it uploads confidential files to public sandboxes and burns the API quota before lunch.

## 1. Pick enrichments by triage question

| Triage question | Source | Output field |
|---|---|---|
| Whose device / who owns it? | CMDB, EDR device inventory, Intune/Jamf | `asset.owner`, `asset.tier`, `asset.os` |
| Who is the user, are they privileged? | Entra ID / AD, HR feed, PAM | `user.department`, `user.privileged`, `user.manager` |
| Has this entity been seen before? | Case management, SIEM 30-day history | `prior_cases`, `first_seen` |
| Is the IOC known bad? | TI platform, commercial feeds, VirusTotal, AbuseIPDB | `ti.verdict`, `ti.sources`, `ti.first_seen` |
| Where did the sign-in come from? | GeoIP, ASN, known VPN/proxy lists | `src.country`, `src.asn`, `src.is_hosting` |
| What does the file do? | Internal sandbox, EDR file analysis | `sandbox.verdict`, `sandbox.behaviours` |

Do not add an enrichment no analyst uses. Ask triage analysts which lookups they repeat; measure usage after a month.

## 2. Data-sharing rules (decide before you build)

- **Hashes and public IPs/domains** may be looked up in external services per your TI policy.
- **Files, URLs with tokens, email bodies, internal hostnames** must not go to public multi-tenant sandboxes or reputation services. Use a private sandbox tenant or on-prem detonation.
- Strip query strings from URLs before external lookup (`https://x/reset?token=...` leaks a credential).
- Record the policy in the playbook description and enforce it in code (allow-list of fields sent per connector).

## 3. Normalize verdicts

Every source maps to one enum so decisions stay simple:

| Normalized | VirusTotal example | AbuseIPDB example | Internal TI |
|---|---|---|---|
| `malicious` | ≥ 5 engines malicious and first seen > 24 h | confidence ≥ 90 | indicator active, confidence high |
| `suspicious` | 1-4 engines | 25-89 | confidence medium |
| `benign` | 0 engines, prevalent, signed by trusted publisher | 0 and known provider ASN | on allow-list |
| `unknown` | not found / error | not found | not found |

Keep the raw response in the case for analysts; decide on the normalized value only.

## 4. Caching and quotas

- Cache by `(source, indicator)` with TTL: 24 h for reputation, 7 days for WHOIS/ASN, 1 h for identity risk.
- Deduplicate within a run: 40 alerts with the same C2 IP → 1 lookup.
- Handle 429 with exponential backoff and a cap (`max_iterations: 3`), then return `unknown`, never fail the run.
- Track daily quota consumption per connector and alert at 80%.

```kusto
// Sentinel: Logic App enrichment failures per action (quota and auth problems show up here first)
AzureDiagnostics
| where TimeGenerated > ago(1d) and Category == "WorkflowRuntime" and status_s == "Failed"
| summarize failures=count() by resource_workflowName_s, resource_actionName_s, code_s
| order by failures desc
```

## 5. Write back

Post one structured comment per incident, not one per lookup:

```text
[Enrichment v3] host WS-0412 (tier 2, owner j.doe, Finance) | user j.doe (not privileged, MFA: yes)
IP 203.0.113.50: malicious (internal TI high, AbuseIPDB 97) | prior cases on host: 0 in 90d
Sandbox: not submitted (policy: internal file) | duration 8.2 s
```

Also set incident tags/custom fields so queues can sort by `asset.tier` and `ti.verdict`.

## 6. Quality checks

- Sample 20 enriched incidents per month: are fields correct and current (CMDB owner left the company)?
- Monitor the share of `unknown` verdicts per source; a sudden rise means an API or key problem.
- Version the enrichment output format; downstream decisions and dashboards depend on it.

## Related skills

`soar-playbook-design`, `alert-triage`, `ioc-assessment`, `automation-risk-review`, `playbook-testing`

## References

- VirusTotal API v3: https://docs.virustotal.com/reference/overview
- AbuseIPDB API: https://docs.abuseipdb.com/
- Microsoft Sentinel entities and enrichment: https://learn.microsoft.com/en-us/azure/sentinel/entities
- FIRST Traffic Light Protocol 2.0: https://www.first.org/tlp/
