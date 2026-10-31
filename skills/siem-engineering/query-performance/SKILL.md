---
name: query-performance
description: Diagnose and optimize slow or expensive SIEM queries and scheduled detections in Splunk, Sentinel/KQL and Elastic — time scoping, indexed filtering, avoiding leading wildcards, accelerated data models, summary indexes, schedule windows and cost. Use when searches time out, scheduled detections skip or lag, or SIEM compute/query cost is too high.
license: MIT
metadata:
  category: siem-engineering
  version: "2.0.0"
  verification: documented
---

# SIEM Query Performance

## Universal principles

1. **Narrow time first**, then the most selective indexed filter (index/table, sourcetype, EventCode).
2. **Filter before transform**: `where`/`search` before `stats`/`join`/`extend`.
3. **Avoid leading wildcards** and unanchored regex on large text fields.
4. **Project/fields** early to reduce data moved.
5. **Aggregate instead of join** where possible.
6. **Pre-compute**: accelerated data models/tstats (Splunk), summary rules/materialized views (Sentinel summary rules), transforms/rollups (Elastic).

## Platform specifics

| Platform | Tools | Tips |
|---|---|---|
| Splunk | Job Inspector (`search.log`, command durations), `| tstats` | Use `TERM()`/`PREFIX()` for indexed tokens; avoid `transaction`; check scheduler skipped searches: `index=_internal sourcetype=scheduler status=skipped` |
| Sentinel / KQL | Query stats (CPU, data scanned), `materialize()` for reused subqueries | `has` over `contains`; `summarize` before `join`; put the smaller table on the left of `join`; time filter on `TimeGenerated` first; Basic/Auxiliary tables cost per query |
| Elastic | Search Profiler, slow log | Query `keyword` fields for exact match; avoid script queries; use `filter` context (cached) |

## Scheduled detection hygiene

- Lookback ≥ schedule interval + ingestion delay (e.g. run every 5 min over last 10 min) to avoid gaps; dedupe overlaps.
- Stagger schedules (not all at :00).
- Monitor skipped/delayed runs and duration trends.

## Before/after record

`Query | Runtime before | Data scanned | Change | Runtime after | Result parity check (same rows?)` — always confirm optimization didn't change results.

## Related skills

`splunk-spl-investigation`, `sentinel-kql-investigation`, `elastic-investigation`, `detection-lifecycle`

## References

- Splunk search optimization: https://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutoptimization
- KQL best practices: https://learn.microsoft.com/en-us/kusto/query/best-practices
- Elasticsearch tune for search speed: https://www.elastic.co/guide/en/elasticsearch/reference/current/tune-for-search-speed.html
