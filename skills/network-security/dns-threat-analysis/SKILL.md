---
name: dns-threat-analysis
description: Detect malicious DNS activity — newly registered/rare domains, DGA patterns, DNS tunnelling, fast-flux, NXDOMAIN spikes, DoH bypass, dangling records and resolver abuse — using resolver, Sysmon 22, Zeek and passive DNS data. Use when hunting C2 over DNS, investigating suspicious domains, or reviewing DNS security controls.
license: MIT
metadata:
  category: network-security
  version: "2.0.0"
  verification: documented
---

# DNS Threat Analysis

## Signals

| Threat | Indicators |
|---|---|
| C2 to new infrastructure | Domain age < 30 days (WHOIS/RDAP), low global popularity (not in Tranco top 1M), first-seen in org recently |
| DGA | Many NXDOMAIN from one host, high-entropy labels, consonant runs, sequential TLD patterns |
| Tunnelling / exfil | Long subdomains (> 50 chars), high unique-subdomain count per parent domain, TXT/NULL/CNAME heavy, steady query rate |
| Fast-flux | Many A records with short TTL across diverse ASNs |
| DoH/DoT bypass | Connections to public resolvers on 443/853 from non-browser processes |
| Hijacked/dangling | CNAME to deprovisioned cloud resource (S3, Azure, Heroku) — subdomain takeover |

## Queries

Zeek (`dns.log`, JSON):
```sh
# Hosts with most NXDOMAIN responses
jq -r 'select(.rcode_name=="NXDOMAIN") | ."id.orig_h"' dns.log | sort | uniq -c | sort -rn | head
# Unique subdomains per registered domain (rough eTLD+1: last two labels)
jq -r '.query // empty' dns.log | awk -F. 'NF>2{print $(NF-1)"."$NF" "$0}' | sort -u | awk '{c[$1]++} END{for(d in c) print c[d], d}' | sort -rn | head
```
Sentinel (MDE / DNS Events):
```kusto
DeviceEvents
| where ActionType == "DnsQueryResponse"
| extend q = tostring(parse_json(AdditionalFields).DnsQueryString)
| where strlen(q) > 60
| summarize count(), make_set(q, 10) by DeviceName, InitiatingProcessFileName
```
Splunk (Sysmon 22): `index=sysmon EventCode=22 | eval len=len(QueryName) | where len>60 | stats count dc(QueryName) by host, Image`

Compute Shannon entropy of labels in the SIEM (KQL lacks a built-in; implement with `extract_all` + counts or a function) or offline in Python.

## Enrichment

Passive DNS (historical resolutions), RDAP/WHOIS creation date, certificate transparency (crt.sh) for the domain, hosting ASN, threat intel lookups. Record the lookup date — reputation changes.

## Controls

Protective DNS / RPZ blocking of known-bad and newly observed domains, block outbound DNS except via corporate resolvers, log resolver queries with client IP (not just forwarders), DNSSEC validation, monitor for dangling CNAMEs.

## Related skills

`beaconing-hunt`, `zeek-log-analysis`, `ioc-assessment`, `external-attack-surface-review`

## References

- MITRE ATT&CK T1071.004 DNS / T1568.002 DGA / T1572 Protocol Tunneling: https://attack.mitre.org/techniques/T1071/004/
- CISA Protective DNS: https://www.cisa.gov/resources-tools/services/protective-domain-name-system-dns-resolver
- NIST SP 800-81-2 Secure DNS Deployment Guide: https://csrc.nist.gov/pubs/sp/800/81/2/final
