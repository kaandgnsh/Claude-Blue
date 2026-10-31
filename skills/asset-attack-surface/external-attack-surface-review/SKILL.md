---
name: external-attack-surface-review
description: Map and review your organization's own internet-facing attack surface — domains and subdomains (certificate transparency, DNS), IP ranges and ASNs, exposed services and versions (Shodan/Censys data on your assets), cloud endpoints, dangling DNS, exposed admin panels and edge devices — and prioritize fixes. Use for external exposure assessments, after acquisitions, or when a new edge-device vulnerability is announced.
license: MIT
metadata:
  category: asset-attack-surface
  version: "2.0.0"
  verification: documented
---

# External Attack Surface Review

Scope: assets your organization owns or is authorized to assess. Confirm ownership before any active probing.

## Discover

```sh
# Subdomains from certificate transparency
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | tr '[:upper:]' '[:lower:]' | sed 's/^\*\.//' | sort -u > ct.txt
# Passive subdomain enumeration (authorized use of APIs)
subfinder -d example.com -silent > subfinder.txt
cat ct.txt subfinder.txt | sort -u > subs.txt
# Resolve and find live web services
dnsx -l subs.txt -a -resp -silent > resolved.txt
httpx -l subs.txt -title -status-code -tech-detect -silent > web.txt
```
IP space: RIR/WHOIS for your ASNs and allocations, cloud provider IP inventories (`cloud-exposure-review`). Passive service data: Shodan/Censys queries limited to your ranges/domains (`net:203.0.113.0/24`, `ssl.cert.subject.cn:example.com`).

## Review

| Finding | Priority |
|---|---|
| Edge devices (VPN, firewalls, file transfer, remote access gateways) with vulnerable versions | P1 — frequent KEV entries |
| Admin interfaces exposed (RDP, SSH with passwords, management GUIs, Kubernetes API, database ports, Elasticsearch/Redis/MongoDB) | P1 |
| Dangling DNS (CNAME to deprovisioned cloud resources) | P1 — subdomain takeover |
| Staging/dev sites with real data or no auth | P2 |
| Expired/weak TLS, missing HSTS | P3 |
| Unknown assets (no owner) | Investigate: shadow IT or third party |

Dangling CNAME check: `dig +short CNAME sub.example.com` → target returns NXDOMAIN or a provider "no such bucket/app" page.

## Safety

Active scanning (port scans, nuclei) only on assets confirmed as yours, with authorization, low rate, and coordination with the SOC and hosting providers.

## Related skills

`cloud-exposure-review`, `exposure-validation`, `shadow-it-discovery`, `emergency-vulnerability-response`

## References

- CISA Cyber Hygiene vulnerability scanning service: https://www.cisa.gov/cyber-hygiene-services
- ProjectDiscovery tools (subfinder, dnsx, httpx): https://docs.projectdiscovery.io/
- crt.sh: https://crt.sh/
- OWASP subdomain takeover guidance (WSTG): https://owasp.org/www-project-web-security-testing-guide/
