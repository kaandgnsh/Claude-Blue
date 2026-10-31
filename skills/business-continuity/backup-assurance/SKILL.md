---
name: backup-assurance
description: Verify that backups will actually restore after ransomware or disaster — coverage vs. critical systems, 3-2-1-1-0 rule, immutability (object lock, hardened repositories), credential isolation of backup infrastructure, encryption, restore testing with measured RTO/RPO, and backup-attack detection. Use when assessing backup resilience, preparing for ransomware, or after backup deletion attempts.
license: MIT
metadata:
  category: business-continuity
  version: "2.0.0"
  verification: documented
---

# Backup Assurance

## 3-2-1-1-0

3 copies, 2 media/types, 1 off-site, **1 immutable or offline**, **0 errors** after verified restore tests.

## Assessment checklist

| Area | Check |
|---|---|
| Coverage | Every system in `critical-service-mapping` has backups meeting its RPO; SaaS data (M365, Google, Salesforce) and cloud resources (databases, buckets, Kubernetes state/etcd, IaC state) included; identity systems (AD system state for forest recovery) |
| Immutability | S3 Object Lock (compliance mode), Azure immutable blob storage, hardened Linux repositories (e.g. Veeam hardened repo), tape/air gap; retention long enough to predate typical dwell time (≥ 30 days) |
| Isolation | Backup servers not domain-joined to production AD (or separate admin forest), separate MFA-protected admin accounts, consoles not reachable from user networks, backup credentials not stored on production hosts |
| Encryption | Backups encrypted; keys stored separately and recoverable when primary IdP/KMS is down |
| Monitoring | Alerts on backup job failures, retention changes, deletion of restore points, MFA disable on backup consoles, mass deletion API calls |
| Restore testing | Regular tests per tier (critical quarterly), including full system restores and AD forest recovery drills; measured actual RTO vs. target |
| Documentation | Restore runbooks accessible offline |

## Ransomware-specific

Attackers target backups first: Veeam/other backup server CVEs, deleting VSS copies, wiping repositories, changing retention, disabling immutability. Ensure detections exist (`ransomware-response` precursors) and that at least one copy is out of reach of domain admin credentials.

## Restore test record

`System | Backup source | Restore point age | Started | Completed | RTO target/actual | Data validated by | Issues`

## Related skills

`ransomware-recovery`, `recovery-exercise`, `critical-service-mapping`, `ransomware-response`

## References

- CISA #StopRansomware Guide (backup guidance): https://www.cisa.gov/stopransomware/ransomware-guide
- NIST SP 800-209 Security Guidelines for Storage Infrastructure: https://csrc.nist.gov/pubs/sp/800/209/final
- AWS S3 Object Lock: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- Microsoft AD Forest Recovery Guide: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-guide
