---
name: advisory-triage
description: Triage incoming security advisories and vulnerability disclosures — vendor PSIRT bulletins, CISA alerts and KEV additions, CERT/CC and national CERT notes, researcher reports to your PSIRT — for relevance, credibility, severity and required action, and route them to owners. Use when the advisory inbox needs processing, a major disclosure breaks, or you run a product security (PSIRT) intake.
license: MIT
metadata:
  category: security-research
  version: "2.0.0"
  verification: documented
---

# Advisory Triage

## Intake sources

CISA (KEV feed, advisories, ICS advisories), vendor PSIRTs (Microsoft MSRC update guide, Cisco, Fortinet, Palo Alto, Ivanti, Citrix, VMware/Broadcom, Atlassian…), CERT/CC, national CERTs (NCSC, BSI, CERT-EU), OSS ecosystems (GitHub Security Advisories, OSV), threat intel vendors, and inbound reports to your own `security.txt` / bug bounty.

KEV feed polling example:
```sh
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  | jq -r --arg d "$(date -u -d '-7 days' +%F)" '.vulnerabilities[] | select(.dateAdded >= $d) | [.dateAdded,.cveID,.vendorProject,.product,.dueDate] | @tsv'
```

## Triage questions

1. **Relevance**: do we run the product/version/configuration? (asset inventory, SBOMs)
2. **Credibility**: vendor-confirmed? CVE assigned? Independent reproduction? Rumours on social media need verification.
3. **Exploitation**: in KEV / vendor says exploited / public PoC / EPSS.
4. **Exposure**: internet-facing instances?
5. **Action**: patch/mitigate (`vuln-prioritization`, `emergency-vulnerability-response`), detection content (`intel-to-detection`), hunt for prior compromise, communicate to owners.

## Inbound vulnerability reports (PSIRT)

Acknowledge quickly (target ≤ 3 business days), validate in a test environment, assign severity (CVSS v4), agree disclosure timeline with the reporter (coordinated disclosure, e.g. 90 days), publish advisory with fixed versions and CVE, credit the researcher.

## Output

`Advisory | Product/CVE | Relevant (assets) | Exploited | Exposure | Priority | Owner | Action | Due`

## Related skills

`vuln-prioritization`, `emergency-vulnerability-response`, `cve-technical-analysis`, `intel-to-detection`

## References

- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST PSIRT Services Framework: https://www.first.org/standards/frameworks/psirts/
- ISO/IEC 29147 vulnerability disclosure (standard; purchase required)
- RFC 9116 security.txt: https://www.rfc-editor.org/rfc/rfc9116
