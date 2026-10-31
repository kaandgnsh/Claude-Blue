---
name: data-discovery
description: Discover where sensitive data lives — structured (databases, warehouses) and unstructured (file shares, SharePoint/Drive, buckets, endpoints, logs, code repos) — using scanners (Macie, Purview, Google DLP/Sensitive Data Protection, open-source detectors), and build a sensitive-data inventory with owners. Use when preparing classification or DLP projects, building privacy records of processing, or scoping breach impact.
license: MIT
metadata:
  category: data-security
  version: "2.0.0"
  verification: documented
---

# Sensitive Data Discovery

## Tools by location

| Location | Tool |
|---|---|
| AWS S3 | Amazon Macie (managed identifiers + custom), automated sensitive data discovery |
| Azure / M365 / on-prem files | Microsoft Purview Data Map / Information Protection scanner, Content explorer |
| GCP | Sensitive Data Protection (Cloud DLP) discovery for BigQuery, Cloud SQL, Cloud Storage |
| Databases | Column-name and content sampling: `information_schema.columns` + regex on samples; commercial DSPM |
| Code/logs | Secret scanners (`secret-scanning`), log PII scanning in the pipeline |
| Endpoints | Endpoint DLP discovery, Purview endpoint content scanning |

Database quick pass (PostgreSQL):
```sql
SELECT table_schema, table_name, column_name, data_type
FROM information_schema.columns
WHERE column_name ~* '(ssn|social|passport|iban|card|cc_num|dob|birth|email|phone|address|tax|salary|diagnosis)'
ORDER BY 1, 2;
```
Then sample values (with approval, read-only, small `LIMIT`) to confirm.

## Method

1. Prioritize by risk: internet-facing stores, shared drives with broad access, analytics copies, backups, dev/test environments with production data.
2. Scan with sampling; record detector, confidence and counts — not raw values.
3. Validate false positives (test data, synthetic records).
4. Assign owner and classification for each store; record legal basis/retention where personal data.
5. Remediate: delete unnecessary copies, mask/tokenize in non-prod, restrict access, encrypt.

## Inventory record

`Store | Location | Data types | Est. records | Classification | Owner | Access breadth | Encryption | Retention | Action`

## Safety

Discovery scanners read sensitive content: use least-privilege service identities, keep results metadata-only, protect findings (they are a map of sensitive data).

## Related skills

`data-classification`, `data-retention-review`, `dpia`, `secret-scanning`

## References

- Amazon Macie sensitive data discovery: https://docs.aws.amazon.com/macie/latest/user/data-classification.html
- Microsoft Purview Data Map: https://learn.microsoft.com/en-us/purview/concept-elastic-data-map
- Google Sensitive Data Protection discovery: https://cloud.google.com/sensitive-data-protection/docs/data-profiles
