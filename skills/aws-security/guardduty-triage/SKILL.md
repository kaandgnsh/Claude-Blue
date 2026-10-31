---
name: guardduty-triage
description: Triage Amazon GuardDuty findings (and correlated Security Hub/Detective data) — understand finding types (UnauthorizedAccess, CredentialAccess, Recon, CryptoCurrency, Exfiltration, Runtime, Malware Protection, Attack Sequence), validate with CloudTrail/VPC/DNS logs, and respond. Use when a GuardDuty finding fires or when tuning GuardDuty suppression rules.
license: MIT
metadata:
  category: aws-security
  version: "2.0.0"
  verification: documented
---

# GuardDuty Triage

## Get finding details

```sh
aws guardduty list-detectors
aws guardduty list-findings --detector-id <id> --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}'
aws guardduty get-findings --detector-id <id> --finding-ids <fid> > finding.json
jq '.Findings[0] | {Type, Severity, Resource, Service: .Service | {Action, Evidence, Count, EventFirstSeen, EventLastSeen}}' finding.json
```
Finding type format: `ThreatPurpose:ResourceTypeAffected/ThreatFamilyName.DetectionMechanism!Artifact`, e.g. `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`.

## High-priority types (examples)

| Finding | Meaning | First checks |
|---|---|---|
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` / `.InsideAWS` | EC2 role credentials used from another host | Instance compromise (SSRF/IMDSv1?); CloudTrail for that session key |
| `CredentialAccess:IAMUser/AnomalousBehavior`, `Discovery:IAMUser/AnomalousBehavior` | ML-anomalous API use | Who/where; `cloudtrail-investigation` |
| `Stealth:IAMUser/CloudTrailLoggingDisabled` | Trail stopped | Immediate incident |
| `Policy:IAMUser/RootCredentialUsage` | Root used | Verify with owner |
| `CryptoCurrency:EC2/BitcoinTool.B!DNS` | Mining pool DNS from instance | Instance compromise |
| `Backdoor:EC2/C&CActivity.B!DNS` | Known C2 domain lookup | Isolate instance |
| `Execution:Runtime/*`, `PrivilegeEscalation:Runtime/*` | Runtime Monitoring on EC2/EKS/ECS | Process/container details in finding |
| `Exfiltration:S3/AnomalousBehavior`, `Impact:S3/*` | Unusual S3 data access/deletion | S3 data events, Macie for data sensitivity |
| `AttackSequence:*` | GuardDuty-correlated multi-stage sequence (extended threat detection) | Treat as incident |

Finding type names change over time — consult the current finding types list.

## Validate

Correlate with CloudTrail (API activity of the principal), VPC Flow Logs (connections), Route 53 Resolver logs (DNS), EKS audit logs; Amazon Detective graphs if enabled. Check if the source IP is your own scanner/pen test (document and suppress narrowly).

## Respond

EC2: isolate by replacing security groups with an isolation SG (no inbound/outbound), snapshot EBS, capture memory if possible (`forensic-imaging`), detach/disable instance profile credentials (revoke role sessions). IAM: `aws-credential-compromise`. S3: block public access, review bucket policy.

## Suppression

Suppression rules should match **finding type + specific resource/IP** (e.g., vulnerability scanner IP for `Recon:EC2/Portscan`), never entire finding types.

## Related skills

`cloudtrail-investigation`, `aws-credential-compromise`, `cloud-incident-response`, `alert-triage`

## References

- GuardDuty finding types: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html
- GuardDuty remediation guidance: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html
- AWS Security Incident Response Guide: https://docs.aws.amazon.com/security-ir/latest/userguide/
