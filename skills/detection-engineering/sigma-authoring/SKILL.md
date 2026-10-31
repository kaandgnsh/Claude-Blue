---
name: sigma-authoring
description: Write high-quality Sigma detection rules — correct logsource, field names from the Sigma taxonomy, modifiers (contains, endswith, re, cidr, all), conditions, filters, metadata (ATT&CK tags, falsepositives, level) — and validate them with sigma check. Use when creating a vendor-neutral detection, contributing to SigmaHQ, or translating a hunt query into a rule.
license: MIT
metadata:
  category: detection-engineering
  version: "2.0.0"
  verification: tested
---

# Sigma Rule Authoring

## Rule skeleton

```yaml
title: Certutil Download From Remote URL
id: 0f8d2c4e-7a3b-4e1f-9c6d-2b5a8e1f3c47        # uuid4, never reuse
status: experimental                              # experimental → test → stable
description: Detects certutil.exe used with urlcache to download a file, a common LOLBin ingress technique.
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
author: Claude-Blue
date: 2026-10-31
tags:
  - attack.command-and-control
  - attack.t1105
logsource:
  product: windows
  category: process_creation
detection:
  selection_img:
    - Image|endswith: '\certutil.exe'
    - OriginalFileName: 'CertUtil.exe'
  selection_cli:
    CommandLine|contains|all:
      - 'urlcache'
      - 'http'
  condition: all of selection_*
falsepositives:
  - Administrative scripts that fetch CRLs or certificates via certutil (verify and filter by parent/script path)
level: high
```

## Rules of thumb

- **Logsource** uses generic categories (`process_creation`, `network_connection`, `file_event`, `registry_set`, `ps_script`, `dns_query`) or `product`/`service` (e.g. `windows`/`security`, `aws`/`cloudtrail`, `azure`/`signinlogs`). Field names must match the Sigma taxonomy for that category (Sysmon-style: `Image`, `ParentImage`, `CommandLine`, `OriginalFileName`, `TargetFilename`, `TargetObject`, `DestinationIp`).
- Match on `OriginalFileName` (PE metadata) as well as `Image` to catch renamed binaries.
- Lists under one key are **OR**; keys under one selection are **AND**; `|all` makes list values AND.
- Modifiers: `contains`, `startswith`, `endswith`, `re`, `cidr`, `base64offset|contains`, `windash` (matches `-`/`/` variants), `exists`, `cased`, `fieldref`.
- Name selections/filters with prefixes so conditions read clearly: `selection and not 1 of filter_*`.
- Filters must be specific (full path + parent), not broad (`Image|contains: 'Program Files'` is a bypass invitation — attackers can write to some Program Files subfolders on misconfigured hosts).
- `level`: `informational`/`low`/`medium`/`high`/`critical` reflects expected precision **and** impact.
- Correlation rules (Sigma v2): `type: event_count`, `value_count`, `temporal` with `group-by` and `timespan` for thresholds.

## Validate

```sh
pip install sigma-cli
sigma check rules/                     # schema + issue validators (missing fields, duplicate IDs, etc.)
sigma convert -t splunk -p splunk_windows rules/certutil_download.yml   # sanity-check the produced query
```
Then test against real or emulated telemetry (`detection-testing`).

## Related skills

`sigma-conversion`, `detection-testing`, `alerting-detection-strategy`, `hunt-to-detection`

## References

- Sigma specification & docs: https://sigmahq.io/docs/
- Sigma taxonomy / field names: https://github.com/SigmaHQ/sigma-specification
- SigmaHQ rule repository & conventions: https://github.com/SigmaHQ/sigma
- pySigma / sigma-cli: https://github.com/SigmaHQ/sigma-cli
