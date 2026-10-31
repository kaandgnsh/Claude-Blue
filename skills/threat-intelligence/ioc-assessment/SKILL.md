---
name: ioc-assessment
description: Extract, validate, enrich and score indicators of compromise (IPs, domains, URLs, hashes, emails) from reports, alerts or emails — with a bundled tested extractor that refangs/defangs and filters private IPs — then decide block, alert, hunt or discard with expiry. Use when receiving IOC lists from intel feeds, vendors, ISACs or incidents, or before loading indicators into blocking controls.
license: MIT
metadata:
  category: threat-intelligence
  version: "2.0.0"
  verification: tested
---

# IOC Assessment

## Extract

```sh
python3 scripts/ioc_extract.py report.txt            # JSON by type; refangs hxxp/[.]/[@]
python3 scripts/ioc_extract.py report.txt --defang   # safe to paste into tickets/chat
```
Non-global IPs (RFC 1918, loopback, documentation ranges) are separated into `non_global_ip`. File names that look like domains (`loader.exe`) are ignored.

## Assess each indicator

| Check | Why |
|---|---|
| Type fitness | Hashes are precise but brittle; IPs churn fast (shared hosting, CDNs, cloud); domains last longer; URLs most specific |
| Shared infrastructure | Is the IP a CDN/cloud front (Cloudflare, Akamai, AWS CloudFront), Tor exit, VPN, sinkhole? Blocking it may break business |
| Popularity | Domain in Tranco top list or used by your business → never block blindly |
| Age & context | When was it malicious? Source report date; IPs older than ~30–90 days rarely still malicious |
| Source reliability | Admiralty code: source A–F, information 1–6 |
| Internal sightings | Prevalence in your logs (`incident-scoping` sweeps) |

## Pyramid of Pain

Hash < IP < domain < network/host artefacts < tools < TTPs. Prefer converting IOCs into behaviour detections (`intel-to-detection`) where possible.

## Decision

| Confidence | Specificity | Action |
|---|---|---|
| High | High (unique domain/URL/hash) | Block + alert + retro-hunt |
| High | Low (shared IP) | Alert/hunt only |
| Medium | Any | Alert/hunt, review in 30 days |
| Low / stale | Any | Store for enrichment only |

Always set **expiry** (e.g. IP 30 days, domain 90 days, hash 1 year) and record source + reason.

## Output

`Value (defanged) | Type | Source (reliability) | First/last seen | Context | Internal sightings | Decision | Expiry`

## Related skills

`intel-to-detection`, `stix-taxii-misp`, `incident-scoping`, `dns-threat-analysis`

## References

- David Bianco, Pyramid of Pain: https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
- Tranco list: https://tranco-list.eu/
- NATO Admiralty / source reliability (FM 2-22.3 appendix B): https://irp.fas.org/doddir/army/fm2-22-3.pdf
