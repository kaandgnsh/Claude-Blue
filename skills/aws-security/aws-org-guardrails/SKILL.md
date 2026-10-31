---
name: aws-org-guardrails
description: Design and review AWS Organizations guardrails — SCPs and RCPs (resource control policies), delegated administrators, organization CloudTrail, security tooling accounts, region restrictions, root access management — to prevent dangerous actions across all accounts. Use when building a multi-account landing zone, reviewing Control Tower/SCP coverage, or adding preventive controls after an incident.
license: MIT
metadata:
  category: aws-security
  version: "2.0.0"
  verification: documented
---

# AWS Organization Guardrails

## Account structure

Management account (no workloads), security tooling account (delegated admin for GuardDuty, Security Hub, Access Analyzer, Macie, Detective, Inspector), log archive account (organization trail, immutable buckets), workload OUs (prod/non-prod), sandbox OU, suspended OU.

## High-value SCPs (preventive)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "ProtectSecurityServices", "Effect": "Deny",
     "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors",
                "guardduty:DeleteDetector", "guardduty:DisassociateFromMasterAccount", "guardduty:UpdateDetector",
                "securityhub:DisableSecurityHub", "config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder",
                "access-analyzer:DeleteAnalyzer"],
     "Resource": "*",
     "Condition": {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/SecurityBreakGlass"}}},
    {"Sid": "DenyLeaveOrg", "Effect": "Deny", "Action": "organizations:LeaveOrganization", "Resource": "*"},
    {"Sid": "DenyRootUser", "Effect": "Deny", "Action": "*", "Resource": "*",
     "Condition": {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}}},
    {"Sid": "RegionRestriction", "Effect": "Deny", "NotAction": ["iam:*", "organizations:*", "sts:*", "support:*", "cloudfront:*", "route53:*", "budgets:*"],
     "Resource": "*", "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["eu-west-1", "eu-central-1"]}}}
  ]
}
```
Other common SCPs: deny disabling S3 BPA, require IMDSv2 (`ec2:MetadataHttpTokens`), deny creating IAM users/access keys (force SSO), deny `ram:` sharing outside org. **RCPs** (resource control policies) enforce data perimeters on resources (e.g., deny S3/KMS/Secrets access from principals outside the org: `aws:PrincipalOrgID`).

Centralized **root access management** lets you remove root credentials from member accounts.

## Review

1. `aws organizations list-policies --filter SERVICE_CONTROL_POLICY` and `list-targets-for-policy` — which OUs/accounts are covered.
2. Test policies with the IAM policy simulator / in a sandbox OU before attaching broadly; SCPs never grant, they only limit; they don't apply to the management account.
3. Check exemptions (break-glass roles) are narrow and monitored.
4. Confirm org trail covers all accounts and regions, log archive bucket has Object Lock / restricted access.

## Related skills

`aws-iam-review`, `cloud-logging-baseline`, `cloud-posture-assessment`

## References

- SCPs: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
- RCPs: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html
- AWS data perimeters: https://aws.amazon.com/identity/data-perimeters-on-aws/
- AWS Security Reference Architecture: https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html
- Centralized root access: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user-access-management
