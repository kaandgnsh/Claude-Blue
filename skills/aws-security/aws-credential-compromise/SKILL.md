---
name: aws-credential-compromise
description: Respond to compromised AWS credentials — leaked access keys (e.g. in GitHub), stolen role session tokens, console account takeover — by containing (deactivate keys, revoke role sessions, deny policies), scoping actions in CloudTrail across regions/accounts, removing persistence and recovering. Use when an AWS key is exposed, AWS sends a compromised-key notice, or GuardDuty flags credential misuse.
license: MIT
metadata:
  category: aws-security
  version: "2.0.0"
  verification: documented
---

# AWS Credential Compromise

## Contain (minutes)

```sh
# Long-term key (AKIA...): deactivate (don't delete yet — keep for investigation)
aws iam update-access-key --user-name <user> --access-key-id AKIA... --status Inactive
# Find the owning user if unknown
aws iam list-access-keys --user-name <user>   # or: aws sts get-access-key-info --access-key-id AKIA... (returns account)
# Role sessions (ASIA...): revoke all sessions issued before now via the console "Revoke active sessions",
# which attaches the AWSRevokeOlderSessions inline policy, or attach an equivalent deny:
cat > revoke.json <<'J'
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"2025-03-01T12:00:00Z"}}}]}
J
aws iam put-role-policy --role-name <role> --policy-name RevokeOlderSessions --policy-document file://revoke.json
# Console user: remove login profile / reset password, enforce MFA
aws iam delete-login-profile --user-name <user>
```
If the instance profile credentials were stolen (IMDS), revoking role sessions affects the legitimate instance too — plan a restart/new role.

## Scope (hours)

1. Query **all regions** and **all accounts** reachable (the key's account + any role it assumed) for the key/session (`cloudtrail-investigation`). Include `AccessDenied` attempts — they reveal intent.
2. List everything created/modified: users, keys, roles, policies, trust changes, EC2 instances (cryptomining in many regions), Lambda functions, security groups, snapshots shared, S3 policies, SES/SNS (spam abuse), billing anomalies.
3. Determine data access: S3 data events, `GetSecretValue`, RDS snapshots, DynamoDB exports.
4. Find the exposure source: public repo, CI logs, developer laptop, SSRF to IMDSv1.

## Eradicate & recover

Delete attacker resources (after evidence export), remove persistence (users/keys/roles/trusts/IdPs), rotate other credentials that were accessible (Secrets Manager, Parameter Store, database passwords), enforce IMDSv2, add SCP guardrails (`aws-org-guardrails`), respond to the AWS Support case (AWS may restrict the account until resolved).

## Output

`Key/session | Owner | Exposure source | First malicious use | Regions/accounts | Actions taken by attacker | Resources created | Data accessed | Containment time | Remediation`

## Related skills

`cloudtrail-investigation`, `secret-leak-response`, `guardduty-triage`, `cloud-incident-response`

## References

- AWS: What to do if you inadvertently expose an access key: https://repost.aws/knowledge-center/potential-account-compromise
- Revoking IAM role temporary credentials: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html
- AWS Customer Playbook Framework: https://github.com/aws-samples/aws-customer-playbook-framework
