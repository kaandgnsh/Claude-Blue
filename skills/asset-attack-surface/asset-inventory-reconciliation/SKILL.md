---
name: asset-inventory-reconciliation
description: Reconcile asset inventories across sources — CMDB, AD/Entra, MDM, EDR, vulnerability scanner, cloud APIs, DHCP/NAC, SaaS admin — to find unmanaged, unprotected, unscanned and stale assets, and keep an authoritative inventory. Use when coverage metrics disagree, before audits, when building an asset inventory, or after discovering an unknown system in an incident.
license: MIT
metadata:
  category: asset-attack-surface
  version: "2.0.0"
  verification: documented
---

# Asset Inventory Reconciliation

## Sources and keys

| Source | Typical key fields |
|---|---|
| CMDB | Hostname, serial, owner, business service |
| AD / Entra ID / Intune / Jamf | Computer name, device ID, serial, last check-in |
| EDR | Hostname, sensor/device ID, MAC, IP, last seen |
| Vulnerability scanner | IP, hostname, MAC, last scanned, auth success |
| Cloud (AWS/Azure/GCP) | Instance/resource ID, tags (owner, env), private/public IPs |
| DHCP/NAC/switch tables | MAC, IP, port |
| Kubernetes | Node names, cluster |

## Method

1. Export each source with timestamps.
2. Normalize: lowercase hostnames, strip domain suffixes (keep FQDN separately), MAC format `aa:bb:cc:dd:ee:ff`, serial uppercase.
3. Match by strongest key first (serial / cloud instance ID / MAC), then hostname, then IP+time.
4. Produce a matrix of asset × source presence and identify gap categories:

| Gap | Meaning |
|---|---|
| In network/cloud, not in CMDB | Unknown/unowned asset |
| In CMDB/AD, not in EDR | Unprotected |
| Not in scanner (or auth failing) | Unassessed |
| In EDR, not seen 30+ days | Stale or decommissioned — retire records |
| No owner tag | Unaccountable |

```python
import csv
def load(path, key):
    return {r[key].strip().lower().split(".")[0]: r for r in csv.DictReader(open(path))}
cmdb, edr, scan = load("cmdb.csv", "hostname"), load("edr.csv", "hostname"), load("scanner.csv", "hostname")
for host in sorted(set(cmdb) | set(edr) | set(scan)):
    print(host, "cmdb" if host in cmdb else "-", "edr" if host in edr else "-", "scan" if host in scan else "-")
```

## Sustain

Automate weekly; feed gaps to owners as tickets; track coverage metrics (`detection-coverage-metrics`, `edr-coverage-health`).

## Related skills

`asset-criticality-tiering`, `edr-coverage-health`, `shadow-it-discovery`, `scan-result-triage`

## References

- CIS Controls v8.1 Control 1 (Inventory and Control of Enterprise Assets): https://www.cisecurity.org/controls/inventory-and-control-of-enterprise-assets
- NIST SP 1800-5 IT Asset Management: https://www.nccoe.nist.gov/it-asset-management
