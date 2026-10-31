---
name: scc-findings-triage
description: Triage Google Cloud Security Command Center findings — Security Health Analytics misconfigurations, Event Threat Detection (anomalous IAM grants, malware/mining, exfiltration), Container Threat Detection, VM Threat Detection, attack exposure scores — validate with audit logs and respond. Use when SCC findings arrive, when setting SCC mute rules, or when prioritizing GCP security work.
license: MIT
metadata:
  category: gcp-security
  version: "2.0.0"
  verification: documented
---

# Security Command Center Triage

## List findings

```sh
gcloud scc findings list organizations/ORG_ID --location=global \
  --filter='state="ACTIVE" AND (severity="CRITICAL" OR severity="HIGH")' \
  --format='table(finding.category, finding.resourceName, finding.severity, finding.eventTime)'
gcloud scc findings list organizations/ORG_ID --location=global --filter='category="Persistence: IAM Anomalous Grant"' --format=json
```
(SCC API v2 uses `--location`; flags vary by gcloud version.)

## Finding families

| Source | Examples | Triage |
|---|---|---|
| Security Health Analytics | `PUBLIC_BUCKET_ACL`, `OPEN_FIREWALL`, `SERVICE_ACCOUNT_KEY_NOT_ROTATED`, `PUBLIC_SQL_INSTANCE`, `MFA_NOT_ENFORCED` | Misconfiguration → owner remediation, prioritize by exposure |
| Event Threat Detection | `Persistence: IAM Anomalous Grant`, `Initial Access: Leaked Credentials`, `Exfiltration: BigQuery Data Exfiltration`, `Malware: Bad Domain`, `Execution: Cryptocurrency Mining` | Threat → validate in audit logs (`gcp-audit-log-investigation`), incident if confirmed |
| Container Threat Detection | `Added Binary Executed`, `Reverse Shell`, `Malicious Script Executed` | `container-incident` |
| VM Threat Detection | Cryptomining/kernel rootkit detection via memory scanning | Isolate VM, forensics |
| Attack path simulation | Attack exposure score on high-value resources | Fix chokepoint misconfigurations first |

## Response basics

- Leaked credential / anomalous grant: remove binding, disable SA keys, review principal activity.
- Mining: stop/isolate VM (snapshot disk first), check how it was created (`instances.insert` caller), quota abuse across regions.
- Public data: enable public access prevention, check Data Access logs (if enabled) for access.

## Mute rules

Mute only well-understood, documented exceptions with specific resource filters (e.g., a known public website bucket), never whole categories; review mute rules quarterly.

## Related skills

`gcp-audit-log-investigation`, `gcp-iam-review`, `cloud-posture-assessment`, `alert-triage`

## References

- Security Command Center overview: https://cloud.google.com/security-command-center/docs/security-command-center-overview
- Event Threat Detection findings: https://cloud.google.com/security-command-center/docs/concepts-event-threat-detection-overview
- Responding to threat findings: https://cloud.google.com/security-command-center/docs/how-to-investigate-threats
