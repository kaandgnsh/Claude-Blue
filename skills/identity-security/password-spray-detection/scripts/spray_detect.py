#!/usr/bin/env python3
"""Detect password spraying and brute force in authentication logs (stdlib only).

Input CSV columns: ts,user,src,outcome  (outcome: success|failure; ts ISO-8601 or epoch seconds).
Flags sources that fail against many distinct users within a sliding window (spray) or many
times against one user (brute force), and lists any successful logons from flagged sources.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone


def epoch(value: str) -> float:
    value = value.strip()
    try:
        return float(value)
    except ValueError:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def detect(rows, window: int, spray_users: int, brute_attempts: int):
    events = sorted(((epoch(r["ts"]), r["user"].strip().lower(), r["src"].strip(), r["outcome"].strip().lower()) for r in rows))
    failures = defaultdict(deque)  # src -> deque of (ts, user)
    flagged = {}
    for ts, user, src, outcome in events:
        if outcome != "failure":
            continue
        q = failures[src]
        q.append((ts, user))
        while q and q[0][0] < ts - window:
            q.popleft()
        users = {u for _, u in q}
        per_user = max(sum(1 for _, u in q if u == x) for x in users)
        kind = None
        if len(users) >= spray_users:
            kind = "spray"
        elif per_user >= brute_attempts:
            kind = "brute-force"
        if kind:
            entry = flagged.setdefault(src, {"source": src, "type": kind, "first_flagged": iso(ts),
                                             "max_distinct_users_in_window": 0, "max_attempts_one_user": 0, "users": set()})
            if kind == "spray":
                entry["type"] = "spray"
            entry["max_distinct_users_in_window"] = max(entry["max_distinct_users_in_window"], len(users))
            entry["max_attempts_one_user"] = max(entry["max_attempts_one_user"], per_user)
            entry["users"].update(users)
    successes = [
        {"time": iso(ts), "user": user, "source": src}
        for ts, user, src, outcome in events if outcome == "success" and src in flagged
    ]
    results = []
    for entry in flagged.values():
        entry["targeted_users"] = len(entry.pop("users"))
        results.append(entry)
    results.sort(key=lambda e: -e["max_distinct_users_in_window"])
    return {"flagged_sources": results, "successes_from_flagged_sources": successes}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv")
    ap.add_argument("--window", type=int, default=3600, help="sliding window seconds (default 3600)")
    ap.add_argument("--spray-users", type=int, default=10, help="distinct users failed from one source")
    ap.add_argument("--brute-attempts", type=int, default=20, help="failures against one user from one source")
    args = ap.parse_args(argv)
    with open(args.csv, newline="", encoding="utf-8") as handle:
        result = detect(csv.DictReader(handle), args.window, args.spray_users, args.brute_attempts)
    json.dump(result, sys.stdout, indent=2)
    print()
    return 1 if result["successes_from_flagged_sources"] else 0


if __name__ == "__main__":
    sys.exit(main())
