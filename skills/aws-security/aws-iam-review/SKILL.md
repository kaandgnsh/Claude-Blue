---
name: aws-iam-review
description: Review AWS IAM for over-privilege and escalation paths — admin/wildcard policies, PassRole and other escalation actions, risky trust policies (external accounts, wildcard principals, weak OIDC conditions), stale users and keys, root usage, unused access — with IAM Access Analyzer, credential reports and a bundled tested policy linter. Use for AWS account security reviews, least-privilege projects, or after credential compromise.
license: MIT
metadata:
  category: aws-security
  version: "2.0.0"
  verification: tested
---

# AWS IAM Review

## Collect

```sh
aws iam get-account-authorization-details > auth.json          # all users, roles, groups, policies (incl. trust)
python3 scripts/iam_policy_lint.py auth.json --min-severity medium   # bundled linter (exit 1 on critical)
aws iam generate-credential-report && aws iam get-credential-report --query Content --output text | base64 -d > cred.csv
aws accessanalyzer list-findings --analyzer-arn <external-access-analyzer-arn> --filter '{"status":{"eq":["ACTIVE"]}}'
aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://policy.json
```
IAM Access Analyzer: **external access** analyzer (resources shared outside the zone of trust), **unused access** analyzer (unused roles, keys, permissions), and policy generation from CloudTrail activity for least privilege.

## Credential report checks (`cred.csv`)

- `root`: `access_key_1_active` must be false; MFA on; `password_last_used` recent = investigate.
- Users with `password_enabled` and no `mfa_active`.
- Access keys older than 90 days (`access_key_1_last_rotated`) or unused (`access_key_1_last_used_date` N/A).
- Users with console + keys — prefer SSO (IAM Identity Center) for humans; no long-term keys for humans.

## Trust policy red flags

- `"Principal": {"AWS": "*"}` or `"*"` without strict conditions.
- Cross-account trust to unknown accounts; third-party roles without `sts:ExternalId` condition (confused deputy).
- OIDC federation (GitHub Actions, EKS IRSA) without `sub` restriction — e.g. `token.actions.githubusercontent.com:sub` must name repo and branch/environment.
- SAML providers you don't recognize.

## Escalation actions (if granted broadly)

`iam:PassRole` with compute creation (`ec2:RunInstances`, `lambda:CreateFunction`, `glue:CreateDevEndpoint`, `cloudformation:CreateStack`), `iam:CreatePolicyVersion`, `iam:Attach*/Put*Policy`, `iam:CreateAccessKey` on other users, `iam:UpdateAssumeRolePolicy`, `ssm:SendCommand`/`StartSession` on privileged instances, `lambda:UpdateFunctionCode` on privileged functions.

## Output

`Principal | Finding | Evidence (policy/statement) | Severity | Fix | Owner` plus metrics: users without MFA, keys > 90 days, admin principals count, external trusts.

## Related skills

`aws-org-guardrails`, `aws-credential-compromise`, `cloudtrail-investigation`, `privileged-access-review`

## References

- IAM security best practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- IAM Access Analyzer: https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html
- Credential report: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html
- Rhino Security Labs AWS IAM privilege escalation methods: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
