---
name: campaign-correlation
description: Correlate incidents and indicators into campaigns and activity clusters using the Diamond Model, infrastructure pivoting (passive DNS, certificates, WHOIS/RDAP, hosting patterns, JA3/JA4/JARM), malware code overlap and TTP similarity, with disciplined confidence and attribution caution. Use when linking multiple incidents, expanding infrastructure from one IOC, or assessing whether activity matches a known actor.
license: MIT
metadata:
  category: threat-intelligence
  version: "2.0.0"
  verification: documented
---

# Campaign Correlation

## Diamond Model per event

Adversary — Capability (malware/tool/exploit) — Infrastructure (domains/IPs/accounts) — Victim; plus meta-features (timestamp, phase, result, direction, methodology). Clusters form where events share vertices.

## Infrastructure pivots

| Pivot | Source | Caution |
|---|---|---|
| Passive DNS (domain ↔ IP history) | Commercial/community PDNS | Shared hosting creates false links |
| TLS certificates (serial, subject, SAN, issuance time) | crt.sh, Censys, Shodan | Let's Encrypt certs are generic; look at unique SANs/subjects |
| Server fingerprints (JARM, JA4S/JA4X, HTTP headers/favicons hash) | Scan engines | Default configs of common frameworks overlap widely |
| WHOIS/RDAP registrant, registrar, NS, creation time patterns | RDAP | Privacy protection hides data; patterns (same NS + registrar + naming style + time) still useful |
| Hosting (ASN, provider, open ports) | Scan engines | Bulletproof vs. mainstream hosting |
| Malware config/code overlap | Sandboxes, YARA | Shared builders/leaked source |

## Method

1. Record each linking observation with source and date.
2. Weight links: unique artefacts (custom SSL subject, unique URL path, same config key) > common artefacts (same ASN).
3. Require ≥ 2 independent strong links before merging clusters.
4. Name internal clusters neutrally (`CB-CLUSTER-2026-07`) — map to public actor names only with explicit confidence and the overlap that justifies it.
5. Use competing hypotheses (another actor, shared tooling, false flag).

## Output

```
Cluster <id>: events <n> (<dates>)
Shared infrastructure: <items + link strength>
Shared capability: <tools/configs>
TTP overlap: <ATT&CK + procedures>
Assessment: <same operator likely/possible> (confidence) — overlap with public actor <name>: <basis>
Gaps / next pivots: <>
```

## Related skills

`ioc-assessment`, `intel-report-writing`, `phishing-campaign-scope`, `malware-report`

## References

- Diamond Model of Intrusion Analysis: https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf
- crt.sh certificate transparency search: https://crt.sh/
- JARM: https://github.com/salesforce/jarm
- JA4+: https://github.com/FoxIO-LLC/ja4
