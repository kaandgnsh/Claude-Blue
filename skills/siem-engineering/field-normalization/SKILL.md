---
name: field-normalization
description: Design and validate field normalization across security data models — Splunk CIM, Microsoft ASIM, Elastic ECS, OCSF, Google UDM — including mapping tables, value normalization (action/outcome, user/host formats), and parser testing. Use when building parsers, writing cross-source detections, or debugging rules that miss data due to field differences.
license: MIT
metadata:
  category: siem-engineering
  version: "2.0.0"
  verification: documented
---

# Field Normalization

## Crosswalk (common fields)

| Concept | Splunk CIM | Microsoft ASIM | Elastic ECS | OCSF |
|---|---|---|---|---|
| Source IP | `src` / `src_ip` | `SrcIpAddr` | `source.ip` | `src_endpoint.ip` |
| Destination IP | `dest` / `dest_ip` | `DstIpAddr` | `destination.ip` | `dst_endpoint.ip` |
| User | `user` | `TargetUsername` / `ActorUsername` | `user.name` | `user.name` / `actor.user.name` |
| Host | `dest` / `dvc` | `DvcHostname` | `host.name` | `device.hostname` |
| Process path | `process_path` | `TargetProcessName` | `process.executable` | `process.file.path` |
| Command line | `process` | `TargetProcessCommandLine` | `process.command_line` | `process.cmd_line` |
| Parent process | `parent_process_name` | `ActingProcessName` | `process.parent.name` | `process.parent_process.name` |
| Outcome | `action` (success/failure) | `EventResult` (Success/Failure/Partial/NA) | `event.outcome` | `status_id` / `status` |
| File hash | `file_hash` | `TargetFileSHA256` | `file.hash.sha256` | `file.hashes[]` |

Verify against the current schema versions; names above are the commonly used ones.

## Value normalization rules

- Users: decide canonical form (UPN lowercase; `DOMAIN\user` → `user@domain`) and keep original in a separate field.
- Hosts: short name vs. FQDN — keep both; lowercase.
- IPs: separate IPv4/IPv6 handling, strip ports into their own field.
- Time: UTC ISO-8601; keep source timezone.
- Outcome: map vendor codes (e.g. 4625 → failure; `ResultType != "0"` → failure) to a fixed vocabulary.

## Parser test

For each parser keep sample raw events and expected normalized output; run in CI (`detection-as-code`). Spot-check live data: `fieldsummary` (Splunk), `getschema`/`summarize count() by isempty(field)` (KQL), field statistics in Discover (Elastic).

## Detection impact

Write detections against normalized fields **only** when the fields are reliably populated for all relevant sources; otherwise the rule silently misses sources. Document per-rule which sources the normalized view includes.

## Related skills

`log-source-onboarding`, `sigma-conversion`, `correlation-rule-design`

## References

- Splunk CIM: https://docs.splunk.com/Documentation/CIM/latest/User/Overview
- Microsoft ASIM: https://learn.microsoft.com/en-us/azure/sentinel/normalization
- Elastic ECS: https://www.elastic.co/guide/en/ecs/current/index.html
- OCSF schema: https://schema.ocsf.io/
