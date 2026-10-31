---
name: intel-to-detection
description: Turn threat intelligence (reports, advisories, IOC feeds) into defensive action — exposure check, retro-hunt, behaviour detections from TTPs, IOC watchlists with expiry, and mitigations — and track what was done. Use when a new threat report or CISA/vendor advisory arrives and you must answer "are we affected and are we covered?".
license: MIT
metadata:
  category: threat-intelligence
  version: "2.0.0"
  verification: documented
---

# Intel to Detection

## Workflow

1. **Relevance**: do we run the affected technology / are we in the targeted sector or region? (asset inventory, `external-attack-surface-review`)
2. **Exposure**: vulnerable versions present? internet-facing? (`vuln-prioritization`, CISA KEV check)
3. **Retro-hunt IOCs** over maximum retention (`ioc-assessment` first to filter junk): DNS, proxy, firewall, EDR, email.
4. **Extract TTPs at procedure level** ("uses `rundll32` to run DLL exported `DllRegisterServer` from `%APPDATA%`"), map to ATT&CK.
5. **Check coverage** for each TTP (`attack-coverage-mapping`): telemetry? detection? tested?
6. **Build** missing detections (Sigma/YARA/Suricata), test with emulation where possible.
7. **Mitigate**: patch, config hardening, block lists.
8. **Track**: one ticket per report with checklist; report status to requester.

## Tracking template

```
Intel: <report/advisory id, date, TLP>   Requester: <>
Relevant: yes/no (why)   Exposure: <assets/versions>
Retro-hunt: <sources, window, results>
TTPs → coverage:
  T1xxx.yyy <procedure> | telemetry y/n | detection id/none | tested date | action
Detections created: <ids>   Mitigations: <>
Status: complete / pending (blockers)
```

## Watchlist hygiene

IOC watchlists must carry source, added date, expiry and owner; expired entries auto-removed. Prefer domain/URL over IP; never load CDN/cloud provider IP ranges as block indicators.

## Related skills

`ioc-assessment`, `attack-coverage-mapping`, `sigma-authoring`, `emergency-vulnerability-response`

## References

- CISA cybersecurity advisories: https://www.cisa.gov/news-events/cybersecurity-advisories
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- MITRE CTID Threat Report ATT&CK Mapper (TRAM): https://github.com/center-for-threat-informed-defense/tram
