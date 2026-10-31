---
name: cloudtrail-investigation
description: Investigate AWS activity with CloudTrail — Event history (lookup-events), CloudTrail Lake SQL, Athena over S3 logs — tracing identities through AssumeRole chains, finding persistence, privilege escalation, defense evasion and data access; includes a tested summarizer script. Use when investigating a suspicious AWS principal, access key, console login or GuardDuty finding.
license: MIT
metadata:
  category: aws-security
  version: "2.0.0"
  verification: tested
---

# CloudTrail Investigation

## Get the data

```sh
# Last 90 days of management events (Event history), per key or user — slow, 2 req/s per account/region
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... \
  --start-time 2025-03-01T00:00:00Z --max-results 50 > lookup.json
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=alice --region us-east-1 > alice.json
# Summarize (bundled): identities, IPs, user agents, regions, high-risk API calls
python3 scripts/cloudtrail_summary.py lookup.json
python3 scripts/cloudtrail_summary.py s3-export/*.json.gz
```
Event history is per region — query every region (attackers love unused regions), and `us-east-1` for global services (IAM, STS console sign-in events).

CloudTrail Lake:
```sql
SELECT eventTime, eventName, sourceIPAddress, userAgent, errorCode
FROM <event_data_store_id>
WHERE userIdentity.accessKeyId = 'AKIA...' AND eventTime > '2025-03-01 00:00:00'
ORDER BY eventTime
```
Athena (organization trail table): filter on partition columns (`region`, date) first; `useridentity.arn`, `eventname`, `sourceipaddress`, `errorcode`.

## Trace identity

- `userIdentity.type`: `IAMUser`, `AssumedRole`, `Root`, `FederatedUser`, `AWSService`.
- For AssumedRole, follow the chain: find the `AssumeRole`/`AssumeRoleWithSAML`/`AssumeRoleWithWebIdentity` event whose `responseElements.credentials.accessKeyId` equals the session's `accessKeyId`; its `userIdentity` is the caller. `sourceIdentity` (if set) survives chaining.
- Temporary keys start `ASIA`, long-term `AKIA`.

## What to look for

| Tactic | Events |
|---|---|
| Discovery | `GetCallerIdentity`, `ListBuckets`, `DescribeInstances`, `GetAccountAuthorizationDetails`, many `AccessDenied` (permission probing) |
| Persistence | `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `UpdateAssumeRolePolicy` (trust to external account), new IdP (`CreateSAMLProvider`/`CreateOpenIDConnectProvider`), Lambda/EventBridge backdoors |
| Privilege escalation | `AttachUserPolicy`/`PutRolePolicy` with admin, `CreatePolicyVersion` + `SetDefaultPolicyVersion`, `PassRole` + `RunInstances`/`CreateFunction` |
| Defense evasion | `StopLogging`, `DeleteTrail`, `PutEventSelectors`, `DeleteDetector` (GuardDuty), `DeleteFlowLogs`, region usage outside baseline |
| Credential access | `GetSecretValue`, `GetParameter --with-decryption`, `GetPasswordData` |
| Exfiltration/impact | S3 data events (`GetObject` volume — requires data events enabled), `ModifySnapshotAttribute` (share snapshot to external account), `PutBucketPolicy` public, `DeleteObject`/KMS key disable (ransom) |

Note `GetObject` and other data-plane events only exist if **data events** were enabled for the bucket.

## Output

Timeline (UTC) of the principal's actions, list of created/modified resources (for eradication), source IPs/ASNs/user agents, data accessed, and logging gaps.

## Related skills

`aws-credential-compromise`, `guardduty-triage`, `aws-iam-review`, `cloud-incident-response`

## References

- CloudTrail record contents: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
- lookup-events CLI: https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html
- CloudTrail Lake: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html
- Invictus IR "AWS cheatsheet": https://github.com/invictus-ir/aws-cheatsheet
