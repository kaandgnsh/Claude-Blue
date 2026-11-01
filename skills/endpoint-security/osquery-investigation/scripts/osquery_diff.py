#!/usr/bin/env python3
"""Diff osquery results against a baseline to surface new persistence, listeners, keys or modules (stdlib only).

Inputs are JSON files produced by `osqueryi --json "<query>"` (a list of row objects) or Fleet/osquery
result logs (JSON lines with "name", "hostIdentifier", "columns" and, for differential packs, "action").
Rows are compared on the key columns given with --key (default: all columns except volatile ones such
as pid, uptime, start_time, mtime, atime). Fleet result logs are grouped per host.

  python3 osquery_diff.py --baseline startup_baseline.json --current startup_now.json --key name --key path
Output: JSON {"added": [...], "removed": [...]} (per host for result logs). Exit 1 when rows were added.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

VOLATILE = {"pid", "parent", "uptime", "start_time", "mtime", "atime", "ctime", "btime", "time", "unixTime",
            "calendarTime", "epoch", "counter", "resident_size", "total_size", "user_time", "system_time",
            "disk_bytes_read", "disk_bytes_written", "threads", "handle_count", "elapsed_time", "percent_processor_time"}


def load(path: Path) -> dict[str, list[dict]]:
    """Return {host: rows}; osqueryi output uses host '-'."""
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return {}
    if text.startswith("["):
        return {"-": json.loads(text)}
    hosts: dict[str, list[dict]] = defaultdict(list)
    for line in text.splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("action") == "removed":
            continue
        host = rec.get("hostIdentifier", "-")
        if "columns" in rec:
            hosts[host].append(rec["columns"])
        elif "snapshot" in rec:
            hosts[host].extend(rec["snapshot"])
        else:
            hosts[host].append(rec)
    return hosts


def row_key(row: dict, keys: list[str] | None):
    cols = keys or sorted(k for k in row if k not in VOLATILE)
    return tuple((k, str(row.get(k, ""))) for k in cols)


def diff(baseline: dict, current: dict, keys):
    report = {}
    for host in sorted(set(baseline) | set(current)):
        old = {row_key(r, keys): r for r in baseline.get(host, [])}
        new = {row_key(r, keys): r for r in current.get(host, [])}
        added = [new[k] for k in new.keys() - old.keys()]
        removed = [old[k] for k in old.keys() - new.keys()]
        if host not in baseline:
            report[host] = {"note": "host has no baseline", "added": added, "removed": []}
        elif added or removed:
            report[host] = {"added": added, "removed": removed}
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline", required=True, type=Path)
    ap.add_argument("--current", required=True, type=Path)
    ap.add_argument("--key", action="append", help="column(s) that identify a row; repeatable")
    args = ap.parse_args(argv)
    report = diff(load(args.baseline), load(args.current), args.key)
    if set(report) <= {"-"}:
        out = report.get("-", {"added": [], "removed": []})
    else:
        out = report
    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    print()
    added = sum(len(v["added"]) for v in report.values())
    removed = sum(len(v["removed"]) for v in report.values())
    print(f"hosts_changed={len(report)} added={added} removed={removed}", file=sys.stderr)
    return 1 if added else 0


if __name__ == "__main__":
    sys.exit(main())
