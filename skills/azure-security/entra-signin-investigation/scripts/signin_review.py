#!/usr/bin/env python3
"""Flag compromise indicators in exported Microsoft Entra ID sign-in logs (stdlib only).

Accepts either export shape:
  * Microsoft Graph /auditLogs/signIns JSON ({"value": [...]}, a list, or JSON lines; camelCase fields)
  * Log Analytics / Sentinel SigninLogs or AADNonInteractiveUserSignInLogs JSON export (PascalCase fields)
Indicators per user:
  impossible-travel     consecutive successful sign-ins faster than --max-kmh over > 500 km
  spray-then-success    success after >= --fail-count password failures (50126) inside one hour
  mfa-denied-burst      >= 3 MFA failures/denials (500121) inside 10 minutes
  legacy-auth-success   success with a legacy protocol client (IMAP, POP, SMTP, EAS, other clients)
  scripted-client       success from scripting user agents or admin tooling apps for review
  session-new-country   one SessionId seen from more than one country (token replay candidate)
Output: JSON list of findings. Exit 0.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

LEGACY = {"exchange activesync", "imap4", "pop3", "authenticated smtp", "smtp", "other clients",
          "exchange web services", "autodiscover", "mapi over http", "offline address book", "reporting web services",
          "exchange online powershell", "universal outlook"}
SCRIPTED_UA = re.compile(r"python-requests|axios|go-http-client|curl/|okhttp|powershell|aiohttp|node-fetch", re.I)
ADMIN_APPS = {"microsoft azure powershell", "microsoft azure cli", "graph explorer", "azure active directory powershell",
              "microsoft graph command line tools"}


def first(rec, *paths):
    for path in paths:
        cur = rec
        for key in path.split("."):
            if isinstance(cur, str) and cur.startswith("{"):
                try:
                    cur = json.loads(cur)
                except json.JSONDecodeError:
                    cur = None
            cur = cur.get(key) if isinstance(cur, dict) else None
        if cur not in (None, ""):
            return cur
    return None


def normalize(rec):
    when = first(rec, "createdDateTime", "TimeGenerated", "CreatedDateTime")
    code = first(rec, "status.errorCode", "ResultType", "Status.errorCode")
    lat = first(rec, "location.geoCoordinates.latitude", "LocationDetails.geoCoordinates.latitude")
    lon = first(rec, "location.geoCoordinates.longitude", "LocationDetails.geoCoordinates.longitude")
    return {
        "time": datetime.fromisoformat(str(when).replace("Z", "+00:00")[:32]),
        "time_raw": when,
        "user": str(first(rec, "userPrincipalName", "UserPrincipalName") or "").lower(),
        "ip": first(rec, "ipAddress", "IPAddress"),
        "code": int(code) if code is not None and str(code).lstrip("-").isdigit() else None,
        "country": first(rec, "location.countryOrRegion", "LocationDetails.countryOrRegion"),
        "city": first(rec, "location.city", "LocationDetails.city"),
        "lat": float(lat) if lat is not None else None,
        "lon": float(lon) if lon is not None else None,
        "client": str(first(rec, "clientAppUsed", "ClientAppUsed") or ""),
        "app": str(first(rec, "appDisplayName", "AppDisplayName") or ""),
        "ua": str(first(rec, "userAgent", "UserAgent") or ""),
        "session": first(rec, "sessionId", "SessionId", "correlationId", "CorrelationId"),
    }


def load(path: Path):
    text = path.read_text(encoding="utf-8-sig").strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:  # JSON lines
        data = [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(data, dict):
        data = data.get("value", [data])
    rows = [normalize(r) for r in data]
    return sorted(rows, key=lambda r: r["time"])


def km(a, b):
    lat1, lon1, lat2, lon2 = map(math.radians, (a["lat"], a["lon"], b["lat"], b["lon"]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 6371.0 * 2 * math.asin(math.sqrt(h))


def review(rows, max_kmh=900.0, fail_count=10):
    findings = []

    def add(kind, row, detail):
        findings.append({"indicator": kind, "time": row["time_raw"], "user": row["user"], "ip": row["ip"],
                         "country": row["country"], "app": row["app"], "detail": detail})

    by_user = defaultdict(list)
    for row in rows:
        by_user[row["user"]].append(row)
    sessions = defaultdict(set)

    for user, items in by_user.items():
        last_ok = None
        for i, row in enumerate(items):
            ok = row["code"] == 0
            if ok and row["lat"] is not None and last_ok is not None:
                dist = km(last_ok, row)
                hours = max((row["time"] - last_ok["time"]).total_seconds() / 3600, 1 / 60)
                if dist > 500 and dist / hours > max_kmh:
                    add("impossible-travel", row,
                        f"{dist:.0f} km from {last_ok['city']}, {last_ok['country']} in {hours * 60:.0f} min ({dist / hours:.0f} km/h)")
            if ok and row["lat"] is not None:
                last_ok = row
            if ok:
                window = [r for r in items[:i] if r["code"] == 50126 and row["time"] - r["time"] <= timedelta(hours=1)]
                if len(window) >= fail_count:
                    add("spray-then-success", row, f"success after {len(window)} invalid-password failures in 1 h")
                if row["client"].lower() in LEGACY:
                    add("legacy-auth-success", row, f"client '{row['client']}' bypasses modern MFA controls")
                if SCRIPTED_UA.search(row["ua"]) or row["app"].lower() in ADMIN_APPS:
                    add("scripted-client", row, f"app '{row['app']}', user agent '{row['ua'][:80]}'")
            if row["code"] == 500121:
                burst = [r for r in items[:i + 1] if r["code"] == 500121 and row["time"] - r["time"] <= timedelta(minutes=10)]
                if len(burst) == 3:
                    add("mfa-denied-burst", row, "3 MFA failures/denials within 10 minutes (MFA fatigue?)")
            if row["session"] and row["country"]:
                before = set(sessions[row["session"]])
                sessions[row["session"]].add(row["country"])
                if before and row["country"] not in before:
                    add("session-new-country", row, f"session {row['session']} also used from {sorted(before)}")
    findings.sort(key=lambda f: str(f["time"]))
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("export", type=Path, help="sign-in export (Graph JSON or Log Analytics JSON)")
    ap.add_argument("--max-kmh", type=float, default=900.0)
    ap.add_argument("--fail-count", type=int, default=10)
    args = ap.parse_args(argv)
    findings = review(load(args.export), args.max_kmh, args.fail_count)
    json.dump(findings, sys.stdout, indent=2)
    print()
    print(f"findings={len(findings)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
