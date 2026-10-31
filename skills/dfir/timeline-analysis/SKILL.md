---
name: timeline-analysis
description: Build and analyze a forensic super-timeline from disk images, event logs, EDR and cloud logs (Plaso/log2timeline, EZ tools, or the bundled merge script) to reconstruct attacker activity in UTC. Use when you need to establish sequence of events, patient zero, dwell time, or correlate artefacts from multiple sources.
license: MIT
metadata:
  category: dfir
  version: "2.0.0"
  verification: tested
---

# Timeline Analysis

## Option A — Plaso super-timeline (disk images)

```sh
log2timeline.py --storage-file case.plaso disk.E01
psort.py -o l2tcsv -w timeline.csv case.plaso "date > '2025-03-01 00:00:00' AND date < '2025-03-08 00:00:00'"
```
Plaso can be slow on full images; use `--parsers` (e.g. `win7,!filestat`) or target with `--artifact-filters` to limit scope. Review in Timeline Explorer, Timesketch, or a spreadsheet.

## Option B — Merge exported sources (bundled script)

When you have CSV/JSONL exports (EDR, SIEM, cloud logs, EZ tool output), normalize them to one UTC timeline:

```sh
python3 scripts/merge_timeline.py \
  --source edr=edr.csv:Timestamp \
  --source cloudtrail=ct.jsonl:eventTime \
  --source evtx=evtx.csv:TimeCreated \
  --start 2025-03-01T00:00:00Z --end 2025-03-08T00:00:00Z \
  -o timeline.csv
```
Each `--source` is `label=path:timestamp_field`. ISO-8601, `YYYY-MM-DD HH:MM:SS` (assumed UTC unless `--assume-tz` given) and epoch seconds/milliseconds are parsed. Output columns: `timestamp_utc, source, original_timestamp, summary` (summary = remaining fields, compact JSON). Unparseable timestamps are counted and reported, never silently dropped.

## Analysis method

1. **Anchor events**: alert time, known-bad file creation, first malicious logon. Work backwards and forwards ±window.
2. **Clock discipline**: confirm each source's timezone and skew (e.g., compare a known event recorded in two sources). Windows event logs are UTC internally; many CSV exports are local time.
3. **Look for MACB patterns** ($MFT `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamps; SI earlier than FN suggests timestomping).
4. **Group activity into phases** (initial access, execution, persistence, privilege escalation, lateral movement, collection, exfiltration) and map to ATT&CK.
5. **Annotate gaps** — periods with no telemetry are not periods with no activity.

## Output template

```
Timeline <case> — sources: <list with tz/skew>
Window: <start>–<end> UTC
<UTC> | <source> | <event> | <ATT&CK> | <analyst note>
Key findings: initial access <t>, first lateral movement <t>, exfil <t>
Gaps: <source/time>
```

## Related skills

`windows-artifacts`, `registry-analysis`, `incident-scoping`, `forensic-report`

## References

- Plaso documentation: https://plaso.readthedocs.io/
- Timesketch: https://timesketch.org/
- Eric Zimmerman's tools: https://ericzimmerman.github.io/
