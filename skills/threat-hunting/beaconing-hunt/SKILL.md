---
name: beaconing-hunt
description: Hunt for command-and-control beaconing in proxy, firewall, Zeek or DNS logs using connection-interval regularity (jitter/coefficient of variation), data-size consistency, rarity and long-duration connections — includes a tested stdlib scoring script. Use when hunting for C2 without known IOCs, or validating a suspected implant's network pattern.
license: MIT
metadata:
  category: threat-hunting
  version: "2.0.0"
  verification: tested
---

# Beaconing Hunt

Implants check in on a timer (often with jitter). Look for **many** connections from one source to one destination with **regular intervals** and **similar sizes**, to a destination that is **rare** in the environment.

## Data

Per connection: timestamp, source (host/IP), destination (domain/IP:port), bytes out/in. Sources: Zeek `conn.log`/`http.log`/`ssl.log`, proxy logs, firewall logs, EDR network events, DNS logs (query timing).

## Bundled scorer

```sh
# CSV with columns: ts,src,dst[,bytes]  (ts = ISO-8601 or epoch seconds)
python3 scripts/beacon_score.py conns.csv --min-count 20 --top 25
```
For each `src→dst` pair it reports count, median interval, coefficient of variation (CV = stdev/mean of intervals; lower = more regular), median-absolute-deviation ratio, byte-size CV, and a 0–100 score. CV < 0.1 with ≥ 20 connections is highly regular; implants with 20–50% jitter produce CV ≈ 0.1–0.3. Export Zeek conn.log to CSV with: `zeek-cut -d ts id.orig_h id.resp_h orig_bytes < conn.log | tr '\t' ','`.

## SIEM-native approach

Splunk:
```spl
index=proxy earliest=-24h | sort 0 _time
| streamstats current=f last(_time) as prev by src, dest
| eval delta=_time-prev | where isnotnull(delta)
| stats count avg(delta) as avg stdev(delta) as sd by src, dest
| eval cv=sd/avg | where count>=20 AND cv<0.2 | sort cv
```
Sentinel:
```kusto
CommonSecurityLog
| where TimeGenerated > ago(1d)
| summarize ts=make_list(TimeGenerated, 10000) by SourceIP, DestinationHostName
| where array_length(ts) >= 20
| mv-apply ts to typeof(datetime) on (order by ts asc | extend d = datetime_diff('second', ts, prev(ts)) | summarize avg_d=avg(d), sd=stdev(d))
| extend cv = sd / avg_d | where cv < 0.2 | order by cv asc
```

## Triage of candidates

1. Remove known periodic software: update agents, NTP, EDR/AV cloud, monitoring, M365/Google sync, telemetry (keep an allow-list with owners).
2. Check destination rarity (how many internal hosts talk to it), domain age, certificate (self-signed, recently issued, JA3/JA4 fingerprint), ASN, and process attribution on the host (EDR).
3. Long connections (Zeek `duration` hours) and DNS beaconing (many TXT/NULL queries, long random subdomains) are separate patterns — check both.

## Related skills

`zeek-log-analysis`, `dns-threat-analysis`, `netflow-analysis`, `hypothesis-hunt`

## References

- Active Countermeasures RITA (beacon analysis): https://github.com/activecm/rita
- MITRE ATT&CK T1071 Application Layer Protocol / T1573: https://attack.mitre.org/techniques/T1071/
- Zeek conn.log: https://docs.zeek.org/en/master/logs/conn.html
