---
name: cloud-incident-response
description: Lead incident response in AWS, Azure or GCP — preserve control-plane and data-plane logs, identify compromised identities and resources, contain via identity and network controls, collect forensic snapshots, and recover — with provider-specific commands. Use when a cloud account, subscription, tenant or project is compromised or a cloud workload is breached.
license: MIT
metadata:
  category: cloud-security
  version: "2.0.0"
  verification: documented
---

# Cloud Incident Response

## Phases mapped to providers

| Step | AWS | Azure | GCP |
|---|---|---|---|
| Control-plane logs | CloudTrail (all regions), Organization trail | Activity Log, Entra ID sign-in/audit logs | Cloud Audit Logs (Admin Activity, Data Access) |
| Data-plane logs | S3 data events, VPC Flow Logs, Route 53 Resolver | Storage logs, NSG/VNet flow logs, Key Vault logs | Data Access logs, VPC Flow Logs, Cloud DNS |
| Threat detection | GuardDuty, Security Hub, Detective | Defender for Cloud, Sentinel | Security Command Center |
| Contain identity | Deactivate keys, revoke sessions (`aws-credential-compromise`) | Disable user, `Revoke-MgUserSignInSession`, remove role assignments | Disable SA/keys, remove IAM bindings, revoke OAuth tokens |
| Contain network | Isolation security group, NACL | NSG deny-all on NIC | Firewall rule deny / remove external IP |
| Forensic copy | EBS snapshot → forensic account | Managed disk snapshot → forensic subscription | PD snapshot → forensic project |

## Workflow

1. **Preserve first**: export relevant logs before retention windows expire (CloudTrail Event history 90 days; Azure Activity Log 90 days by default; Entra sign-in logs 7–30 days depending on licence unless exported).
2. **Identify the initial principal** and trace every identity it created or assumed (role chains, service principals, service accounts, federated trusts).
3. **Inventory attacker changes**: new identities/keys, policy changes, compute launched (check all regions), network changes, data shares (snapshots/images shared to external accounts), logging tampering.
4. **Contain in a coordinated window** (`containment-plan`), prioritizing identity: rotate/revoke, then remove persistence.
5. **Forensics** on workloads: snapshot disks, memory capture where feasible, isolate rather than terminate.
6. **Recover**: redeploy from IaC, rotate secrets, re-enable logging and guardrails, monitor for re-entry.
7. **Report**: timeline, data accessed, root cause (leaked keys, misconfig, SSRF, phished admin).

## Cloud-specific pitfalls

- Terminating instances destroys evidence (instance store, memory).
- Attacker-created identities in **other** accounts/tenants via trust relationships.
- Billing anomalies (cryptomining) often first signal — check all regions.
- Provider may also need a support case (account restrictions, abuse notices).

## Related skills

`aws-credential-compromise`, `entra-signin-investigation`, `gcp-audit-log-investigation`, `forensic-imaging`, `cloud-logging-baseline`

## References

- AWS Security Incident Response Guide: https://docs.aws.amazon.com/security-ir/latest/userguide/
- Microsoft incident response playbooks: https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks
- Google Cloud data incident response process: https://cloud.google.com/docs/security/incident-response
- Invictus IR cloud cheat sheets: https://github.com/invictus-ir
