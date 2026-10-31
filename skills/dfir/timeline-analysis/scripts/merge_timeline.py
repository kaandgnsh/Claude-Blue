#!/usr/bin/env python3
"""Merge CSV/JSONL event exports into a single UTC-sorted timeline (stdlib only).

Usage:
  merge_timeline.py --source label=path:field [--source ...] [--start ISO] [--end ISO]
                    [--assume-tz +02:00] [-o out.csv]
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

_OFFSET = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


def parse_offset(text: str) -> timezone:
    m = _OFFSET.match(text)
    if not m:
        raise argparse.ArgumentTypeError(f"invalid offset {text!r}; use +HH:MM")
    sign = 1 if m.group(1) == "+" else -1
    return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))


def parse_time(value, assume_tz: timezone) -> datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d{9,13}(\.\d+)?", text):
        number = float(text)
        if number > 1e11:  # epoch milliseconds
            number /= 1000.0
        return datetime.fromtimestamp(number, tz=timezone.utc)
    text = text.replace("Z", "+00:00")
    if " " in text and "T" not in text:
        text = text.replace(" ", "T", 1)
    # Trim fractional seconds beyond microseconds (e.g. Windows 7-digit ticks).
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=assume_tz)
    return dt.astimezone(timezone.utc)


def read_rows(path: Path):
    if path.suffix.lower() in (".jsonl", ".ndjson", ".json"):
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    yield json.loads(line)
    else:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            yield from csv.DictReader(handle)


def parse_source(spec: str):
    if "=" not in spec or ":" not in spec.split("=", 1)[1]:
        raise argparse.ArgumentTypeError(f"source must be label=path:field, got {spec!r}")
    label, rest = spec.split("=", 1)
    path, field = rest.rsplit(":", 1)
    return label, Path(path), field


def merge(sources, start, end, assume_tz):
    events, bad = [], {}
    for label, path, field in sources:
        for row in read_rows(path):
            ts = parse_time(row.get(field), assume_tz)
            if ts is None:
                bad[label] = bad.get(label, 0) + 1
                continue
            if (start and ts < start) or (end and ts > end):
                continue
            rest = {k: v for k, v in row.items() if k != field and v not in (None, "")}
            events.append((ts, label, str(row.get(field)), json.dumps(rest, sort_keys=True, ensure_ascii=False)))
    events.sort(key=lambda e: (e[0], e[1]))
    return events, bad


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", action="append", required=True, type=parse_source)
    ap.add_argument("--start")
    ap.add_argument("--end")
    ap.add_argument("--assume-tz", type=parse_offset, default=timezone.utc,
                    help="offset for timestamps without timezone (default UTC)")
    ap.add_argument("-o", "--output")
    args = ap.parse_args(argv)
    start = parse_time(args.start, timezone.utc) if args.start else None
    end = parse_time(args.end, timezone.utc) if args.end else None
    events, bad = merge(args.source, start, end, args.assume_tz)
    out = open(args.output, "w", newline="", encoding="utf-8") if args.output else sys.stdout
    try:
        writer = csv.writer(out)
        writer.writerow(["timestamp_utc", "source", "original_timestamp", "summary"])
        for ts, label, original, summary in events:
            writer.writerow([ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), label, original, summary])
    finally:
        if out is not sys.stdout:
            out.close()
    print(f"events={len(events)}", file=sys.stderr)
    for label, count in sorted(bad.items()):
        print(f"WARNING: {count} rows in source {label!r} had unparseable timestamps", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
