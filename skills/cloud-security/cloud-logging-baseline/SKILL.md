---
name: cloud-logging-baseline
description: Define and verify the minimum security logging baseline for AWS, Azure, GCP and major SaaS — what to enable (control plane, data events, identity, network, DNS, Kubernetes), retention, immutability and SIEM forwarding — and find gaps before an incident. Use when onboarding cloud environments, preparing for IR readiness, or after an investigation was blocked by missing logs.
license: MIT
metadata:
  category: cloud-security
  version: "2.0.0"
  verification: documented
---

# Cloud Logging Baseline

## AWS

| Log | Enable | Verify |
|---|---|---|
| CloudTrail org trail, multi-region, log file validation | Yes | `aws cloudtrail describe-trails --query 'trailList[].{n:Name,multi:IsMultiRegionTrail,org:IsOrganizationTrail,validation:LogFileValidationEnabled}'` |
| CloudTrail data events (S3 sensitive buckets, Lambda) | Selectively (cost) | `aws cloudtrail get-event-selectors --trail-name T` |
| VPC Flow Logs | All VPCs | `aws ec2 describe-flow-logs` |
| Route 53 Resolver query logs | Yes | `aws route53resolver list-resolver-query-log-configs` |
| GuardDuty (all regions, org) | Yes | `aws guardduty list-detectors` per region |
| EKS control-plane audit | Yes | `eks-*` |
| Config | Yes | `aws configservice describe-configuration-recorder-status` |

## Azure / Entra

Entra ID sign-in (interactive, non-interactive, service principal, managed identity) and audit logs → Log Analytics/Sentinel (portal retention is short); Azure Activity Log via diagnostic settings at subscription/management group; resource diagnostic logs (Key Vault, Storage, SQL, AKS kube-audit, NSG/VNet flow logs); Microsoft Defender XDR streaming; M365 Unified Audit Log (Purview Audit Standard/Premium retention).
```sh
az monitor diagnostic-settings subscription list --query "value[].{name:name,ws:workspaceId}"
```

## GCP

Admin Activity (always on), **Data Access logs** (off by default except BigQuery — enable for sensitive services), System Event, Policy Denied; VPC Flow Logs per subnet; Cloud DNS logging; organization-level aggregated sink to a locked bucket/BigQuery.
```sh
gcloud logging sinks list --organization=ORG_ID
gcloud projects get-iam-policy PROJECT --format=json | jq '.auditConfigs'
```

## SaaS

Okta System Log, Google Workspace audit, GitHub audit log streaming, Salesforce Event Monitoring, Slack audit logs (Enterprise) — via API to SIEM.

## Retention & integrity

Minimum 1 year (≥ 90 days hot) is common guidance; check regulatory needs (PCI DSS 10.5.1: 12 months, 3 immediately available). Store in a separate log account/subscription/project with restricted delete (S3 Object Lock, immutable blob storage, locked GCS retention policies).

## Gap report

`Environment | Log source | Required | Enabled | Retention | Forwarded to SIEM | Gap | Owner`

## Related skills

`log-source-onboarding`, `aws-org-guardrails`, `cloud-incident-response`, `hunt-data-readiness`

## References

- NSA/CISA Best Practices for Event Logging and Threat Detection: https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection
- AWS security logging guidance (SRA): https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/log-archive.html
- Microsoft Entra monitoring and health: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/
- GCP Cloud Audit Logs: https://cloud.google.com/logging/docs/audit
