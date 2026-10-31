---
name: s3-exposure-review
description: Find and fix Amazon S3 data exposure — account/bucket Block Public Access, bucket policies and ACLs, Object Ownership, cross-account and presigned access, encryption and logging — using Access Analyzer, Macie and CLI checks, and investigate whether exposed data was accessed. Use for S3 posture reviews, a reported open bucket, or before storing sensitive data in S3.
license: MIT
metadata:
  category: aws-security
  version: "2.0.0"
  verification: documented
---

# S3 Exposure Review

## Checks

```sh
aws s3control get-public-access-block --account-id <acct>                   # account-level BPA (all four true)
aws s3api get-public-access-block --bucket B                                  # bucket-level BPA
aws s3api get-bucket-policy-status --bucket B --query PolicyStatus.IsPublic
aws s3api get-bucket-policy --bucket B --query Policy --output text | jq .
aws s3api get-bucket-ownership-controls --bucket B                            # BucketOwnerEnforced disables ACLs
aws s3api get-bucket-acl --bucket B
aws s3api get-bucket-encryption --bucket B
aws s3api get-bucket-logging --bucket B
aws accessanalyzer list-findings --analyzer-arn <arn> --filter '{"resourceType":{"eq":["AWS::S3::Bucket"]},"status":{"eq":["ACTIVE"]}}'
```
Amazon Macie identifies buckets that are public/shared and containing sensitive data (PII, credentials).

## Policy red flags

- `"Principal": "*"` with `s3:GetObject`/`s3:ListBucket` and no restricting `Condition` (`aws:SourceVpce`, `aws:PrincipalOrgID`, `aws:SourceIp`).
- Cross-account principals not in the organization.
- `s3:PutObject` for `*` (malware hosting / content injection).
- ACL grants to `AllUsers`/`AuthenticatedUsers` (any AWS account!).
- Static website buckets holding non-public data.

## Was it accessed? (exposure investigation)

- S3 **server access logs** or CloudTrail **data events** for the bucket — if neither was enabled, access cannot be ruled out; state this clearly.
- Look for `GetObject`/`ListBucket` from IPs outside your organization; unauthenticated requests show requester `-` in server access logs.
- Quantify objects and data classes exposed (inventory + Macie) for `privacy-incident-assessment`.

## Remediate

Enable account-level BPA (with exceptions only for documented public-website buckets, ideally via CloudFront OAC instead), set Object Ownership to BucketOwnerEnforced, scope policies with `aws:PrincipalOrgID`, enable default encryption (SSE-KMS for sensitive), enable data events for sensitive buckets, SCP to deny disabling BPA.

## Related skills

`data-exposure-investigation`, `cloudtrail-investigation`, `aws-org-guardrails`, `cloud-exposure-review`

## References

- S3 Block Public Access: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- S3 security best practices: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html
- Amazon Macie: https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html
