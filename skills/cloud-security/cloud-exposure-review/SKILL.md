---
name: cloud-exposure-review
description: Identify internet exposure across cloud estates — public IPs and load balancers, open security groups/NSGs/firewall rules, public storage and snapshots, exposed databases and managed services, serverless URLs, public container registries — and validate what is actually reachable. Use when mapping the cloud attack surface, after a misconfiguration incident, or before a pen test.
license: MIT
metadata:
  category: cloud-security
  version: "2.0.0"
  verification: documented
---

# Cloud Exposure Review

## Inventory queries

AWS:
```sh
aws ec2 describe-instances --query 'Reservations[].Instances[?PublicIpAddress].[InstanceId,PublicIpAddress,MetadataOptions.HttpTokens]' --output text
aws elbv2 describe-load-balancers --query 'LoadBalancers[?Scheme==`internet-facing`].[LoadBalancerName,DNSName]'
aws rds describe-db-instances --query 'DBInstances[?PubliclyAccessible].[DBInstanceIdentifier,Endpoint.Address]'
aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[].SnapshotId' --output text | xargs -n1 -I{} aws ec2 describe-snapshot-attribute --snapshot-id {} --attribute createVolumePermission --query 'CreateVolumePermissions'
aws lambda list-function-url-configs --function-name F    # per function; AuthType NONE = public
```
Azure (Resource Graph):
```sh
az graph query -q "Resources | where type =~ 'microsoft.network/publicipaddresses' | project name, properties.ipAddress, properties.ipConfiguration.id"
az graph query -q "Resources | where type =~ 'microsoft.storage/storageaccounts' | where properties.allowBlobPublicAccess == true | project name, resourceGroup"
```
GCP (Cloud Asset Inventory):
```sh
gcloud asset search-all-resources --scope=organizations/ORG --asset-types=compute.googleapis.com/Address --query="addressType:EXTERNAL"
gcloud asset search-all-iam-policies --scope=organizations/ORG --query="policy:allUsers OR policy:allAuthenticatedUsers"
```

## Validate reachability

Rules can be shadowed by other layers (NACLs, WAF, private endpoints). Confirm with an external scan of your own IPs (authorized, `external-attack-surface-review`) or provider reachability analyzers (AWS Network Access Analyzer / Reachability Analyzer, Azure Network Watcher, GCP Connectivity Tests).

## Prioritize

Data stores and admin interfaces reachable from the internet first; then compute with privileged identities; then everything else. For each exposed resource record: owner, purpose, data, auth, intended (y/n).

## Related skills

`cloud-posture-assessment`, `s3-exposure-review`, `firewall-rule-review`, `external-attack-surface-review`, `cloud-firewall-build`

## References

- AWS Network Access Analyzer: https://docs.aws.amazon.com/vpc/latest/network-access-analyzer/what-is-network-access-analyzer.html
- Azure Resource Graph: https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview
- GCP Cloud Asset Inventory: https://cloud.google.com/asset-inventory/docs/overview
