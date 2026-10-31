---
name: gcp-service-account-keys
description: Find, assess and eliminate Google Cloud service account key risk — user-managed keys, key age and usage, leaked JSON keys, impersonation as the alternative, Workload Identity Federation for external workloads, and response to an exposed key. Use when auditing service accounts, migrating off JSON keys, or a service account key has leaked.
license: MIT
metadata:
  category: gcp-security
  version: "2.0.0"
  verification: documented
---

# GCP Service Account Keys

User-managed JSON keys are long-lived bearer credentials; leaked keys are a leading cause of GCP compromise.

## Inventory

```sh
for sa in $(gcloud iam service-accounts list --project=P --format='value(email)'); do
  gcloud iam service-accounts keys list --iam-account="$sa" --managed-by=user \
    --format="table[no-heading](name.basename(), validAfterTime, validBeforeTime, disabled)" | sed "s|^|$sa |"
done
# Org-wide via Cloud Asset Inventory
gcloud asset search-all-resources --scope=organizations/ORG_ID --asset-types=iam.googleapis.com/ServiceAccountKey --format="table(name, createTime)"
```
Key usage: Policy Intelligence **service account key insights** / Activity Analyzer (`gcloud policy-intelligence query-activity --activity-type=serviceAccountKeyLastAuthentication --project=P`).

## Reduce

1. Enforce org policies `iam.disableServiceAccountKeyCreation` and `iam.disableServiceAccountKeyUpload` (with exceptions per folder only where unavoidable); consider `iam.serviceAccountKeyExpiryHours`.
2. Replace keys:
   - GCP workloads → attached service accounts (metadata server).
   - Developers/admins → impersonation (`gcloud --impersonate-service-account=...`, `roles/iam.serviceAccountTokenCreator` scoped to the specific SA).
   - External workloads (AWS, Azure, GitHub Actions, on-prem) → **Workload Identity Federation** with attribute conditions (e.g., GitHub `assertion.repository == "org/repo"`).
3. Delete unused keys (no authentication in 90 days).

## Leaked key response

```sh
gcloud iam service-accounts keys disable KEY_ID --iam-account=SA_EMAIL      # immediate
gcloud logging read 'protoPayload.authenticationInfo.serviceAccountKeyName:"KEY_ID"' --freshness=30d --project=P
gcloud iam service-accounts keys delete KEY_ID --iam-account=SA_EMAIL        # after evidence capture
```
Audit logs record `serviceAccountKeyName` for key-based calls — scope all actions by that key across projects where the SA has access (`gcp-audit-log-investigation`), then remove persistence and rotate any secrets it could read.

## Related skills

`gcp-iam-review`, `secret-leak-response`, `gcp-audit-log-investigation`

## References

- Best practices for managing service account keys: https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys
- Workload Identity Federation: https://cloud.google.com/iam/docs/workload-identity-federation
- Service account impersonation: https://cloud.google.com/iam/docs/service-account-impersonation
