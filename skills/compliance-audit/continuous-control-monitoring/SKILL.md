---
name: continuous-control-monitoring
description: Implement continuous control monitoring (CCM) — automated, scheduled checks of security controls via APIs and policy engines (AWS Config/Security Hub, Azure Policy, GCP Org Policy, IdP and EDR reports, Steampipe/Powerpipe, OPA), thresholds, alerting, evidence retention and dashboards. Use when automating compliance evidence, replacing point-in-time audits with ongoing assurance, or building control health dashboards.
license: MIT
metadata:
  category: compliance-audit
  version: "2.0.0"
  verification: documented
---

# Continuous Control Monitoring

## Good CCM candidates

| Control | Automated test | Source |
|---|---|---|
| MFA for all users / admins | % users with MFA registered; % admin sign-ins with phishing-resistant MFA | IdP API / sign-in logs |
| EDR coverage | Healthy agents ÷ inventory | EDR API + CMDB (`edr-coverage-health`) |
| Patch SLA | % critical vulns past SLA | Vuln scanner API |
| Encryption at rest | Non-encrypted volumes/buckets/databases | AWS Config rules, Azure Policy, GCP Org Policy, Prowler |
| Logging enabled | CloudTrail/diagnostic settings present | Config/Policy |
| Public exposure | Public buckets, `0.0.0.0/0` admin ports | CSPM |
| Access reviews | Campaign completion % by due date | IGA |
| Backup | Successful backups and last restore test date | Backup platform API |
| Leavers | Accounts enabled after termination | HR ↔ IdP reconciliation (`joiner-mover-leaver`) |

## Implementation

1. Define each check as code with: control ID, query/API call, pass threshold, frequency, owner, evidence output.
2. Use native policy engines where possible:
   ```sh
   aws configservice describe-compliance-by-config-rule --compliance-types NON_COMPLIANT
   az policy state summarize --management-group MG
   steampipe query "select name, region from aws_s3_bucket where bucket_policy_is_public"
   ```
3. Store results immutably with timestamps (evidence for auditors).
4. Alert owners on threshold breach; track remediation tickets.
5. Dashboard trend per control; report exceptions to governance.

## Pitfalls

Checks that test configuration presence but not effectiveness (policy exists but excludes most users), stale inventories making coverage look good, alert fatigue without owners.

## Related skills

`audit-evidence-package`, `control-mapping`, `security-metric-definition`, `cloud-posture-assessment`

## References

- AWS Config managed rules: https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html
- Azure Policy: https://learn.microsoft.com/en-us/azure/governance/policy/overview
- NIST SP 800-137 Information Security Continuous Monitoring: https://csrc.nist.gov/pubs/sp/800/137/final
- Steampipe: https://steampipe.io/docs
