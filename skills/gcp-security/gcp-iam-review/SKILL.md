---
name: gcp-iam-review
description: Review Google Cloud IAM across organization, folders and projects — basic roles (owner/editor), primitive and external-domain members, allUsers/allAuthenticatedUsers, service account user/token creator grants, default compute service account usage, org policy constraints, IAM recommender insights. Use for GCP security assessments, least-privilege work, or after suspected privilege escalation.
license: MIT
metadata:
  category: gcp-security
  version: "2.0.0"
  verification: documented
---

# GCP IAM Review

## Collect

```sh
gcloud organizations get-iam-policy ORG_ID --format=json > org-iam.json
gcloud resource-manager folders get-iam-policy FOLDER_ID --format=json
gcloud projects get-iam-policy P --format=json > p-iam.json
gcloud asset search-all-iam-policies --scope=organizations/ORG_ID --query="policy:roles/owner" --format=json
gcloud asset analyze-iam-policy --organization=ORG_ID --identity="user:alice@example.com"   # effective access
gcloud recommender recommendations list --project=P --location=global --recommender=google.iam.policy.Recommender
gcloud resource-manager org-policies list --organization=ORG_ID
```
Flatten bindings: `jq -r '.bindings[] | .role as $r | .members[] | [$r, .] | @tsv' p-iam.json | sort`.

## Findings

| Finding | Why |
|---|---|
| `roles/owner` / `roles/editor` (basic roles) on users or SAs | Very broad; editor can act as most SAs |
| `allUsers` / `allAuthenticatedUsers` members | Public / any Google account |
| Members from external domains (`user:x@gmail.com`) | Outside identity governance |
| `roles/iam.serviceAccountUser`, `roles/iam.serviceAccountTokenCreator` at project level | Can impersonate every SA in the project |
| Default compute SA (`PROJECT_NUMBER-compute@developer.gserviceaccount.com`) with Editor and attached to VMs | Any VM compromise = project editor |
| `roles/resourcemanager.organizationAdmin`, `roles/iam.securityAdmin` holders | Can grant themselves anything |
| Missing org policies | `iam.disableServiceAccountKeyCreation`, `iam.allowedPolicyMemberDomains` (domain restricted sharing), `compute.requireOsLogin`, `storage.publicAccessPrevention`, `compute.vmExternalIpAccess` |

## Output

`Resource (org/folder/project) | Member | Role | Inherited? | Last used (recommender) | Risk | Action`

## Related skills

`gcp-service-account-keys`, `gcp-audit-log-investigation`, `privileged-access-review`, `cloud-posture-assessment`

## References

- GCP IAM best practices: https://cloud.google.com/iam/docs/using-iam-securely
- Organization policy constraints: https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints
- IAM Recommender: https://cloud.google.com/policy-intelligence/docs/role-recommendations-overview
- Policy Analyzer: https://cloud.google.com/policy-intelligence/docs/policy-analyzer-overview
