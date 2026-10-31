---
name: data-exposure-investigation
description: Investigate a data exposure — misconfigured storage, public links, leaked database or backup, data posted on leak sites or paste sites, misdirected bulk email — to determine what data, whose, how long exposed, whether accessed, and support notification decisions. Use when sensitive data is found exposed or reported leaked, by researchers, customers, threat intel or internal discovery.
license: MIT
metadata:
  category: data-security
  version: "2.0.0"
  verification: documented
---

# Data Exposure Investigation

## Questions to answer (for legal/privacy)

1. **What** data: fields, classification, record count, data subjects (customers, employees, children), jurisdictions.
2. **How** exposed: public bucket/blob/share link, open database (Elasticsearch/MongoDB without auth), API flaw (`api-abuse-detection`), backup on public storage, insider upload, third party.
3. **When**: exposure start (configuration change time from audit logs) to closure.
4. **Accessed?** By whom: access logs for the window (S3 server access/CloudTrail data events, Azure Storage logs, GCS Data Access logs, SharePoint `AnonymousLinkUsed`/`FileAccessed`, web server logs, database audit). If logs don't exist, state "cannot rule out access".
5. **Spread**: indexed by search engines/Shodan/Grayhat Warfare? Posted on leak/paste sites? Copies with third parties?

## Workflow

1. **Contain**: remove public access (preserve the current config first: export bucket policy/ACL, link settings), rotate any credentials in the data.
2. **Preserve**: configuration snapshots, access logs, copies of leaked samples obtained by intel (handle as restricted data).
3. **Quantify**: inventory of exposed objects; scan with classification tools (Macie, Purview, DLP scanners) to count records and data types; deduplicate subjects.
4. **Access analysis**: distinguish your own systems/scanners, security researchers (often single access), and bulk downloads by unknown parties.
5. **Hand off** facts to `privacy-incident-assessment` and legal for notification decisions.

## Output

```
Exposure: <asset> via <mechanism>  Window: <start>–<end> UTC (evidence)
Data: <types>, <n records>, <n unique subjects>, jurisdictions <>
Access: <n> external requests by <n> sources; bulk download: yes/no; logs coverage: <>
Containment: <time/action>  Credentials rotated: <>
Open questions: <>
```

## Related skills

`s3-exposure-review`, `privacy-incident-assessment`, `api-abuse-detection`, `m365-audit-investigation`

## References

- NIST SP 1800-29 Data Confidentiality: Detect, Respond to, and Recover from Data Breaches: https://www.nccoe.nist.gov/data-confidentiality-detect-respond-and-recover-data-breaches
- EDPB Guidelines 9/2022 on personal data breach notification: https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-92022-personal-data-breach-notification-under_en
