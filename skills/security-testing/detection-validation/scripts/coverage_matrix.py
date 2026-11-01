#!/usr/bin/env python3
"""Score detection coverage of an emulation run: executed tests vs. alerts the SIEM raised (stdlib only).

Plan (JSON list), one object per executed test:
  {"id": "T-01", "technique": "T1003.001", "host": "WS-12", "executed_at": "2026-10-30T10:00:00Z",
   "expect": ["LSASS Memory Access"], "window_min": 30}
Alerts (CSV export): columns for time, rule name and host; names are set with --time-col,
--rule-col and --host-col (defaults: timestamp, rule, host). Hosts compare case-insensitively
and ignore a DNS suffix (WS-12 == ws-12.corp.example).

Each test is classified:
  detected        an expected rule fired on that host inside the window
  detected-other  only unexpected rules fired on that host inside the window (check mapping/tuning)
  missed          nothing fired on that host inside the window
Latency is seconds from execution to the first matching alert. Output: CSV (default) or JSON,
plus a summary on stderr. --fail-under N exits 1 when detected% < N.
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def parse_time(value: str) -> datetime:
    value = value.strip()
    if value.isdigit():
        number = int(value)
        return datetime.fromtimestamp(number / 1000 if number > 10**11 else number, tz=timezone.utc)
    value = value.replace("Z", "+00:00")
    if " " in value and "T" not in value:
        value = value.replace(" ", "T", 1)
    stamp = datetime.fromisoformat(value)
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


def norm_host(host: str) -> str:
    return host.strip().lower().split(".")[0]


def load_alerts(path: Path, time_col: str, rule_col: str, host_col: str):
    alerts, bad = [], 0
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        missing = {time_col, rule_col, host_col} - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"{path}: missing column(s) {sorted(missing)}; have {reader.fieldnames}")
        for row in reader:
            try:
                alerts.append((parse_time(row[time_col]), row[rule_col].strip(), norm_host(row[host_col])))
            except (ValueError, AttributeError):
                bad += 1
    alerts.sort()
    return alerts, bad


def score(plan: list[dict], alerts) -> list[dict]:
    rows = []
    for test in plan:
        start = parse_time(test["executed_at"])
        end = start + timedelta(minutes=int(test.get("window_min", 30)))
        host = norm_host(test["host"])
        expected = {e.lower() for e in test.get("expect", [])}
        hits = [a for a in alerts if start <= a[0] <= end and a[2] == host]
        good = [a for a in hits if a[1].lower() in expected]
        if good:
            status, first = "detected", good[0]
        elif hits:
            status, first = "detected-other", hits[0]
        else:
            status, first = "missed", None
        rows.append({
            "id": test["id"],
            "technique": test.get("technique", ""),
            "host": test["host"],
            "status": status,
            "latency_s": int((first[0] - start).total_seconds()) if first else "",
            "fired": "; ".join(sorted({a[1] for a in hits})),
            "expected": "; ".join(test.get("expect", [])),
        })
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plan", required=True, type=Path)
    ap.add_argument("--alerts", required=True, type=Path)
    ap.add_argument("--time-col", default="timestamp")
    ap.add_argument("--rule-col", default="rule")
    ap.add_argument("--host-col", default="host")
    ap.add_argument("--format", choices=("csv", "json"), default="csv")
    ap.add_argument("--fail-under", type=float, help="exit 1 when detected percentage is below this")
    args = ap.parse_args(argv)

    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    alerts, bad = load_alerts(args.alerts, args.time_col, args.rule_col, args.host_col)
    rows = score(plan, alerts)
    if args.format == "json":
        json.dump(rows, sys.stdout, indent=2)
        print()
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0]) if rows else ["id"])
        writer.writeheader()
        writer.writerows(rows)

    total = len(rows) or 1
    counts = {s: sum(r["status"] == s for r in rows) for s in ("detected", "detected-other", "missed")}
    pct = 100.0 * counts["detected"] / total
    latencies = sorted(r["latency_s"] for r in rows if r["status"] == "detected")
    median = int(statistics.median(latencies)) if latencies else None
    print(f"tests={len(rows)} detected={counts['detected']} detected-other={counts['detected-other']} "
          f"missed={counts['missed']} detected_pct={pct:.1f} median_latency_s={median}", file=sys.stderr)
    if bad:
        print(f"skipped {bad} alert rows with unparseable time", file=sys.stderr)
    return 1 if args.fail_under is not None and pct < args.fail_under else 0


if __name__ == "__main__":
    sys.exit(main())
