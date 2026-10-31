---
name: data-classification
description: Design and operationalize a data classification scheme — levels and handling rules, sensitivity labels (Microsoft Purview, Google Drive labels), auto-labelling with sensitive information types, default labels and encryption — and measure adoption. Use when creating or revising classification policy, deploying labels, or deciding how a data set must be protected.
license: MIT
metadata:
  category: data-security
  version: "2.0.0"
  verification: documented
---

# Data Classification

## Scheme (keep it to 3–5 levels)

| Level | Examples | Handling |
|---|---|---|
| Public | Marketing, published docs | No restrictions |
| Internal | Policies, most email | Employees only; no public sharing |
| Confidential | Customer data, contracts, source code, financials pre-release | Need-to-know; encryption in transit/at rest; external sharing only with approval/secure channels; DLP monitoring |
| Restricted | Credentials/keys, PCI cardholder data, health data, M&A, crown-jewel IP | Strict access lists, encryption with org-controlled keys, no external sharing, logging of all access, DLP blocking |

Regulated categories (GDPR special categories, PHI, PCI, export-controlled) map to the top levels with additional legal requirements.

## Implementation (Microsoft Purview example)

1. Create labels and sublabels with clear names and tooltips; publish label policies to users with a **default label** (e.g., Internal) and mandatory labelling for documents/email where culture allows.
2. Protection: encryption with permissions (Restricted), content marking (headers/watermarks), container labels for Teams/SharePoint sites (privacy, external sharing).
3. **Auto-labelling**: client-side recommendations and service-side policies using SITs (credit card numbers, national IDs, credentials), exact data match for customer records, trainable classifiers.
4. Integrate with DLP policies keyed on labels.
5. Measure: % of files labelled per site/workload, label downgrades (with justification), auto-label simulation results.

## Decision helper

When classifying a dataset, ask: legal/regulatory obligations? impact of disclosure (customers, finances, safety)? integrity criticality? who must access it? Choose the highest applicable level; document the owner and review date.

## Related skills

`data-discovery`, `dlp-alert-triage`, `data-retention-review`, `dpia`

## References

- Microsoft Purview sensitivity labels: https://learn.microsoft.com/en-us/purview/sensitivity-labels
- NIST SP 800-60 (mapping information types to security categories): https://csrc.nist.gov/pubs/sp/800/60/v1/r1/final
- ISO/IEC 27001:2022 Annex A 5.12 Classification of information (standard; purchase required)
