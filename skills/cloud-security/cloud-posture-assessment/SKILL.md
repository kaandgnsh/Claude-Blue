---
name: cloud-posture-assessment
description: Assess multi-cloud security posture (AWS, Azure, GCP) with Prowler, ScoutSuite, Steampipe or native CSPM (Security Hub, Defender for Cloud, Security Command Center) against CIS benchmarks — prioritize findings by exploitability and blast radius rather than count. Use for cloud security assessments, onboarding a new account/subscription/project, or reviewing CSPM output.
license: MIT
metadata:
  category: cloud-security
  version: "2.0.0"
  verification: documented
---

# Cloud Posture Assessment

## Run assessments (read-only credentials)

```sh
prowler aws --compliance cis_4.0_aws -M html json-ocsf          # framework names: prowler aws --list-compliance
prowler azure --az-cli-auth --compliance cis_3.0_azure
prowler gcp --project-ids my-project
scout aws --report-dir scout-report                               # ScoutSuite
steampipe check benchmark.cis_v300                                # Steampipe/Powerpipe mods (version-specific)
```
Native: AWS Security Hub (CIS/FSBP standards), Microsoft Defender for Cloud (secure score, MCSB), GCP Security Command Center (Security Health Analytics). Use a dedicated audit role: AWS `SecurityAudit` + `ViewOnlyAccess`; Azure `Reader` + `Security Reader`; GCP `roles/iam.securityReviewer` + `roles/viewer`.

## Prioritize (not by count)

| Priority | Finding class |
|---|---|
| P1 | Public exposure of data stores (buckets, databases, snapshots), admin services open to internet, root/global admin without MFA, logging disabled, long-lived keys for admins |
| P2 | Over-privileged identities (wildcards, PassRole), cross-account/tenant trusts to unknown parties, unencrypted sensitive stores, IMDSv1 on internet-facing instances |
| P3 | Hardening gaps: rotation, tagging, minor configuration |

Combine with attack-path context: an IMDSv1 instance that is internet-facing **and** has an admin role is far worse than either alone (CNAPP attack paths, or manual graph review).

## Workflow

1. Scope accounts/subscriptions/projects (all of them — shadow accounts are common).
2. Run tools; export JSON/OCSF; deduplicate across tools.
3. Validate top findings manually (false positives from intentional public assets).
4. Assign owners via tags/account ownership; set SLAs; track in tickets.
5. Prevent recurrence with guardrails (SCPs/Azure Policy/Org Policy) and IaC scanning.

## Output

`Cloud/account | Control (CIS ID) | Resource | Severity | Exploitability context | Owner | Fix | Guardrail to prevent`

## Related skills

`cloud-exposure-review`, `aws-org-guardrails`, `azure-rbac-review`, `gcp-iam-review`, `iac-scanning`

## References

- Prowler: https://docs.prowler.com/
- ScoutSuite: https://github.com/nccgroup/ScoutSuite
- CIS cloud benchmarks: https://www.cisecurity.org/cis-benchmarks
- CSA Cloud Controls Matrix: https://cloudsecurityalliance.org/research/cloud-controls-matrix
