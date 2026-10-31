---
name: gcp-audit-log-investigation
description: Investigate Google Cloud activity with Cloud Audit Logs (Admin Activity, Data Access, System Event, Policy Denied) via gcloud logging read, Logs Explorer and BigQuery sinks — IAM policy changes, service account key creation and impersonation, compute and storage abuse, logging tampering. Use when a GCP project or organization may be compromised or an SCC finding needs validation.
license: MIT
metadata:
  category: gcp-security
  version: "2.0.0"
  verification: documented
---

# GCP Audit Log Investigation

## Query with gcloud

```sh
# IAM policy changes in a project (last 7 days)
gcloud logging read 'logName:"cloudaudit.googleapis.com%2Factivity" AND protoPayload.methodName="SetIamPolicy"' \
  --project=P --freshness=7d --format=json > setiam.json
# Service account key creation
gcloud logging read 'protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"' --project=P --freshness=30d
# Activity by a specific principal
gcloud logging read 'protoPayload.authenticationInfo.principalEmail="attacker-sa@P.iam.gserviceaccount.com"' --project=P --freshness=30d \
  --format='table(timestamp, protoPayload.methodName, protoPayload.resourceName, protoPayload.requestMetadata.callerIp)'
# Impersonation (token generation for another SA)
gcloud logging read 'protoPayload.methodName="GenerateAccessToken" OR protoPayload.methodName="SignJwt"' --project=P --freshness=30d
```
Organization-wide: query the aggregated sink (BigQuery) — `cloudaudit_googleapis_com_activity` tables with `protopayload_auditlog.methodName`.

## Key fields

`protoPayload.authenticationInfo.principalEmail`, `protoPayload.authenticationInfo.serviceAccountDelegationInfo` (impersonation chain), `protoPayload.requestMetadata.callerIp` / `callerSuppliedUserAgent`, `protoPayload.methodName`, `protoPayload.resourceName`, `protoPayload.serviceData.policyDelta` (IAM bindings added/removed), `protoPayload.status` (errors).

## What to look for

| Tactic | methodName examples |
|---|---|
| Persistence | `CreateServiceAccountKey`, `CreateServiceAccount`, `SetIamPolicy` (new bindings, esp. `roles/owner`, external domains), new OAuth clients |
| Privilege escalation | `SetIamPolicy` on org/folder/project, `actAs` via `GenerateAccessToken`, `UpdateRole` (custom roles) |
| Defense evasion | `DeleteSink`, `UpdateSink`, `google.logging.v2.ConfigServiceV2.UpdateCmekSettings`, disabling audit configs (`SetIamPolicy` with `auditConfigs` changes), firewall rule changes |
| Execution | `v1.compute.instances.setMetadata` (startup-script, ssh-keys), `instances.insert` in unusual regions (mining) |
| Exfiltration | `storage.objects.get` volume (Data Access logs needed), `storage.buckets.setIamPolicy` with `allUsers`, BigQuery `jobservice.insert` exports |

Data Access logs are **off by default** (except BigQuery) — absence ≠ no access.

## Related skills

`gcp-iam-review`, `gcp-service-account-keys`, `scc-findings-triage`, `cloud-incident-response`

## References

- Cloud Audit Logs overview: https://cloud.google.com/logging/docs/audit
- Audit log entry structure: https://cloud.google.com/logging/docs/audit/understanding-audit-logs
- gcloud logging read: https://cloud.google.com/sdk/gcloud/reference/logging/read
- Logging query language: https://cloud.google.com/logging/docs/view/logging-query-language
