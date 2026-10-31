---
name: stix-taxii-misp
description: Exchange and manage threat intelligence with STIX 2.1, TAXII 2.1 and MISP — object modelling (indicator, malware, threat-actor, relationship, sighting), patterns, TLP markings, feed ingestion, PyMISP automation, warning lists and de-duplication. Use when consuming or publishing intel feeds, configuring a TIP, or converting reports into structured intelligence.
license: MIT
metadata:
  category: threat-intelligence
  version: "2.0.0"
  verification: documented
---

# STIX/TAXII and MISP

## STIX 2.1 indicator

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--3c1f5e0e-7d1a-4b8c-9f5a-2d6e8b4c1a77",
  "created": "2026-10-31T09:00:00.000Z",
  "modified": "2026-10-31T09:00:00.000Z",
  "name": "Loader C2 domain",
  "indicator_types": ["malicious-activity"],
  "pattern": "[domain-name:value = 'upd-cdn.example']",
  "pattern_type": "stix",
  "valid_from": "2026-10-31T09:00:00Z",
  "valid_until": "2027-01-29T09:00:00Z",
  "confidence": 80,
  "object_marking_refs": ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"]
}
```
(`34098fce-...` is the standard TLP:GREEN marking definition for TLP 1.0 in STIX 2.1; TLP 2.0 markings are published as extension definitions — check your TIP's support.) Link indicators to `malware`/`threat-actor`/`attack-pattern` objects with `relationship` objects (`indicates`, `uses`, `attributed-to`), and record internal observations as `sighting` objects.

Validate with `stix2-validator` (`stix2_validator file.json`) and build with the `stix2` Python library.

## TAXII 2.1

Discovery `GET /taxii2/`, API root, collections `GET {api-root}/collections/`, objects `GET {api-root}/collections/{id}/objects/?added_after=...` with `Accept: application/taxii+json;version=2.1`. Use `added_after` + pagination (`next`) for incremental pulls.

## MISP

- Events contain attributes (type/category/to_ids flag) and objects; galaxies/clusters for actors, ATT&CK.
- Use **warninglists** to suppress known-benign values (top domains, cloud ranges, RFC1918) before setting `to_ids`.
- Feeds: enable CIRCL OSINT, abuse.ch, etc.; set caching and correlation carefully (correlation on very common values is expensive).
- PyMISP:
  ```python
  from pymisp import PyMISP
  misp = PyMISP("https://misp.example", "<API_KEY>", ssl=True)
  hits = misp.search(controller="attributes", value="upd-cdn.example", to_ids=True, pythonify=True)
  ```
- Export to SIEM/EDR via `/attributes/restSearch` with `returnFormat` (`csv`, `stix2`, `suricata`, `snort`, `text`) and `to_ids=1`, `last=30d`.

## Data quality rules

Every shared indicator: valid_from/valid_until (expiry), confidence, TLP, source, context (what it indicates). Deduplicate by normalized value; never share victim data externally.

## Related skills

`ioc-assessment`, `intel-to-detection`, `malware-report`

## References

- STIX 2.1 specification: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- TAXII 2.1 specification: https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html
- MISP documentation: https://www.misp-project.org/documentation/
- PyMISP: https://github.com/MISP/PyMISP
