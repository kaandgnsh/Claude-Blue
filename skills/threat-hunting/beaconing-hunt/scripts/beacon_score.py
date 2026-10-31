#!/usr/bin/env python3
"""Score src->dst connection pairs for beacon-like regularity (stdlib only).

Input CSV columns: ts,src,dst[,bytes]. ts may be ISO-8601 or epoch seconds.
"""
from __future__ import annotations

import argparse
import csv
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone


def to_epoch(value: str) -> float:
    value = value.strip()
    try:
        return float(value)
    except ValueError:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()


def cv(values):
    if len(values) < 2:
        return None
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / mean if mean else None


def score_pair(times, sizes):
    times = sorted(times)
    intervals = [b - a for a, b in zip(times, times[1:]) if b > a]
    if len(intervals) < 2:
        return None
    median = statistics.median(intervals)
    mad = statistics.median(abs(i - median) for i in intervals)
    interval_cv = cv(intervals)
    size_cv = cv(sizes) if sizes else None
    regularity = max(0.0, 1.0 - min(interval_cv, 1.0))
    mad_term = max(0.0, 1.0 - min(mad / median, 1.0)) if median else 0.0
    size_term = max(0.0, 1.0 - min(size_cv, 1.0)) if size_cv is not None else 0.5
    volume_term = min(len(times) / 100.0, 1.0)
    score = 100 * (0.4 * regularity + 0.25 * mad_term + 0.2 * size_term + 0.15 * volume_term)
    return {
        "count": len(times),
        "median_interval_s": round(median, 2),
        "interval_cv": round(interval_cv, 4),
        "mad_ratio": round(mad / median, 4) if median else None,
        "size_cv": round(size_cv, 4) if size_cv is not None else None,
        "score": round(score, 1),
    }


def analyse(rows, min_count):
    times, sizes = defaultdict(list), defaultdict(list)
    for row in rows:
        key = (row["src"].strip(), row["dst"].strip())
        times[key].append(to_epoch(row["ts"]))
        if row.get("bytes") not in (None, "", "-"):
            sizes[key].append(float(row["bytes"]))
    results = []
    for key, ts in times.items():
        if len(ts) < min_count:
            continue
        stats = score_pair(ts, sizes.get(key, []))
        if stats:
            results.append({"src": key[0], "dst": key[1], **stats})
    return sorted(results, key=lambda r: r["score"], reverse=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("csv")
    ap.add_argument("--min-count", type=int, default=20)
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args(argv)
    with open(args.csv, newline="", encoding="utf-8") as handle:
        results = analyse(csv.DictReader(handle), args.min_count)
    fields = ["score", "src", "dst", "count", "median_interval_s", "interval_cv", "mad_ratio", "size_cv"]
    writer = csv.DictWriter(sys.stdout, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in results[: args.top]:
        writer.writerow(row)
    return 0


if __name__ == "__main__":
    sys.exit(main())
