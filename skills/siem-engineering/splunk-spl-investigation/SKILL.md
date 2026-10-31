---
name: splunk-spl-investigation
description: Write efficient, correct Splunk SPL for investigations and hunts — tstats over data models, stats/eventstats/streamstats, transaction alternatives, lookups, time handling, subsearch limits — and avoid common correctness traps. Use when querying Splunk (Enterprise/Cloud/ES) during triage, hunting, or detection development.
license: MIT
metadata:
  category: siem-engineering
  version: "2.0.0"
  verification: documented
---

# Splunk SPL for Investigations

## Patterns

```spl
# Always constrain index, sourcetype and time first
index=wineventlog sourcetype=XmlWinEventLog EventCode=4625 earliest=-24h@h latest=now

# Fast counts over accelerated CIM data models
| tstats summariesonly=true count from datamodel=Endpoint.Processes
    where Processes.process_name="certutil.exe" by Processes.dest, Processes.process
| `drop_dm_object_name(Processes)`

# Aggregate instead of transaction
index=proxy user=alice earliest=-7d | stats min(_time) as first max(_time) as last count sum(bytes_out) as out by dest
| convert ctime(first) ctime(last)

# Per-entity baselines with eventstats
index=auth action=failure | stats count by user, src
| eventstats avg(count) as avg stdev(count) as sd by user | where count > avg + 3*sd

# Sequence / interval analysis with streamstats
index=vpn user=* | sort 0 user _time | streamstats current=f last(src_country) as prev_country last(_time) as prev_time by user
| where src_country!=prev_country | eval minutes=round((_time-prev_time)/60,1)

# Enrich with lookups (asset/identity)
... | lookup asset_lookup ip as src OUTPUT owner, criticality

# Rare values
index=sysmon EventCode=1 | rare limit=20 ParentImage by Image
```

## Correctness traps

- **Subsearch limits**: subsearches default to 10,000 results / 60 s and are silently truncated → use `lookup`, `join` alternatives (`stats` by shared key), or `| tstats` with `IN`.
- `join` defaults to 50,000 rows of the subsearch and inner join; prefer `stats values() by key`.
- `dedup` keeps the first event in search order (most recent first by default) — be explicit with `sort`.
- Time: `_time` is event time; `_indextime` is ingest time. Use `earliest`/`latest` with snap-to (`-7d@d`). Display in UTC by setting user timezone or `eval t=strftime(_time,"%Y-%m-%dT%H:%M:%SZ")` after confirming tz.
- `summariesonly=true` only searches accelerated summaries — gaps if acceleration is behind; compare with `summariesonly=false` when coverage matters.
- Field extraction differences: `src` vs `src_ip` vs `Source_Network_Address` depending on TA — verify with `| fieldsummary`.
- Case: field *names* are case-sensitive; values in `search` are case-insensitive, in `where` case-sensitive (`where lower(user)="alice"`).

## Investigation helpers

`| fieldsummary` (what fields exist), `| metadata type=sourcetypes index=X` (what data exists), `| tstats count where index=* by index, sourcetype` (inventory), Job Inspector (performance).

## Related skills

`query-performance`, `field-normalization`, `sigma-conversion`, `correlation-rule-design`

## References

- Splunk Search Reference: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference
- Splunk CIM: https://docs.splunk.com/Documentation/CIM/latest/User/Overview
- Splunk security_content (ESCU) detections: https://research.splunk.com/
