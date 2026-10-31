---
name: elastic-investigation
description: Investigate and hunt in Elastic Security using ES|QL, EQL sequences, KQL/Lucene and ECS field names — process lineage, sequences across hosts, aggregations and timeline — with performance and mapping caveats. Use when querying Elasticsearch/Elastic Security or OpenSearch security data.
license: MIT
metadata:
  category: siem-engineering
  version: "2.0.0"
  verification: documented
---

# Elastic Security Investigation

## Query languages

| Language | Best for |
|---|---|
| KQL (Kibana Query Language) | Quick filters in Discover/Timeline: `process.name : "certutil.exe" and process.args : *urlcache*` |
| EQL | **Sequences** and process trees: ordered events by entity within a time span |
| ES\|QL | Piped aggregations, stats, enrichment (8.11+ GA in later releases) |
| Lucene | Legacy, regex/fuzzy |

## EQL sequence examples

```eql
// Office spawns a script interpreter that makes a network connection within 1 minute
sequence by host.id, process.entity_id with maxspan=1m
  [process where event.type == "start" and process.parent.name in ("winword.exe", "excel.exe") and
     process.name in ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe")]
  [network where event.type == "start"]

// Failed logons followed by success for the same user (brute force success)
sequence by user.name with maxspan=10m
  [authentication where event.outcome == "failure"] with runs=10
  [authentication where event.outcome == "success"]
```

## ES|QL examples

```esql
FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 7 days AND process.parent.name == "services.exe"
| STATS hosts = COUNT_DISTINCT(host.name) BY process.executable
| WHERE hosts <= 2
| SORT hosts ASC
```

## ECS fields to know

`@timestamp`, `host.name`/`host.id`, `user.name`, `process.name`/`process.executable`/`process.command_line`/`process.args`/`process.parent.*`/`process.entity_id`, `file.path`/`file.hash.sha256`, `source.ip`/`destination.ip`/`destination.port`, `dns.question.name`, `url.full`, `event.category`/`event.type`/`event.outcome`/`event.action`.

## Caveats

- `keyword` vs `text` mappings: wildcard and exact matching behave differently; check the index mapping.
- Data stream naming: `logs-<integration>.<dataset>-<namespace>`.
- Sequence queries need consistent entity fields (`process.entity_id` from Elastic Defend; other sources may lack it).
- Large lookbacks on frozen/searchable-snapshot tiers are slow.

## Related skills

`field-normalization`, `sigma-conversion`, `query-performance`, `hypothesis-hunt`

## References

- EQL syntax: https://www.elastic.co/guide/en/elasticsearch/reference/current/eql-syntax.html
- ES|QL reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
- ECS reference: https://www.elastic.co/guide/en/ecs/current/index.html
- Elastic detection rules: https://github.com/elastic/detection-rules
