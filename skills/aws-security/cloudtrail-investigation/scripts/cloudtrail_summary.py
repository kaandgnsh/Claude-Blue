#!/usr/bin/env python3
"""Summarize CloudTrail records for investigation (stdlib only).

Accepts CloudTrail log files ({"Records": [...]}, optionally .gz), JSON-lines exports, or
`aws cloudtrail lookup-events` output ({"Events": [{"CloudTrailEvent": "<json>"}]}).
Reports per-identity activity, error rates, source IPs/user agents and high-risk API calls.
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

HIGH_RISK = {
    "ConsoleLogin", "CreateAccessKey", "CreateUser", "CreateLoginProfile", "UpdateLoginProfile",
    "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "CreatePolicyVersion",
    "SetDefaultPolicyVersion", "UpdateAssumeRolePolicy", "AddUserToGroup", "CreateRole",
    "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteFlowLogs",
    "DisableKey", "ScheduleKeyDeletion", "PutBucketPolicy", "PutBucketAcl", "DeleteBucketPolicy",
    "PutPublicAccessBlock", "DeletePublicAccessBlock", "AuthorizeSecurityGroupIngress",
    "ModifyInstanceAttribute", "CreateKeyPair", "ImportKeyPair", "RunInstances", "GetSecretValue",
    "GetPasswordData", "DeleteDetector", "UpdateDetector", "DisableSecurityHub", "LeaveOrganization",
    "CreateSAMLProvider", "UpdateSAMLProvider", "CreateOpenIDConnectProvider", "GetFederationToken",
    "ModifySnapshotAttribute", "ModifyImageAttribute", "PutBucketReplication", "DeleteObject",
}


def load_records(path: Path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as handle:
        text = handle.read().strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:  # JSON lines: one record per line
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(data, list):
        return data
    if "Records" in data:
        return data["Records"]
    if "Events" in data:  # aws cloudtrail lookup-events
        return [json.loads(e["CloudTrailEvent"]) for e in data["Events"] if "CloudTrailEvent" in e]
    return [data]


def identity(rec) -> str:
    uid = rec.get("userIdentity", {})
    if uid.get("type") == "AssumedRole":
        issuer = uid.get("sessionContext", {}).get("sessionIssuer", {}).get("arn", "")
        return f"{issuer} (session {uid.get('arn', '').rsplit('/', 1)[-1]})"
    return uid.get("arn") or uid.get("invokedBy") or uid.get("type", "unknown")


def summarize(records):
    by_id = defaultdict(lambda: {"events": 0, "errors": 0, "apis": Counter(), "ips": Counter(),
                                 "agents": Counter(), "regions": Counter(), "first": None, "last": None,
                                 "access_keys": set()})
    risky = []
    for rec in records:
        who = identity(rec)
        entry = by_id[who]
        entry["events"] += 1
        name = rec.get("eventName", "")
        entry["apis"][f"{rec.get('eventSource', '').split('.')[0]}:{name}"] += 1
        entry["ips"][rec.get("sourceIPAddress", "")] += 1
        entry["agents"][(rec.get("userAgent") or "")[:80]] += 1
        entry["regions"][rec.get("awsRegion", "")] += 1
        key = rec.get("userIdentity", {}).get("accessKeyId")
        if key:
            entry["access_keys"].add(key)
        t = rec.get("eventTime")
        if t:
            entry["first"] = min(filter(None, [entry["first"], t]))
            entry["last"] = max(filter(None, [entry["last"], t]))
        if rec.get("errorCode"):
            entry["errors"] += 1
        if name in HIGH_RISK:
            risky.append({"time": t, "identity": who, "event": name, "source_ip": rec.get("sourceIPAddress"),
                          "error": rec.get("errorCode"), "region": rec.get("awsRegion"),
                          "request": rec.get("requestParameters")})
    identities = []
    for who, e in sorted(by_id.items(), key=lambda kv: -kv[1]["events"]):
        identities.append({
            "identity": who, "events": e["events"], "errors": e["errors"],
            "error_rate": round(e["errors"] / e["events"], 3), "first": e["first"], "last": e["last"],
            "top_apis": e["apis"].most_common(10), "source_ips": e["ips"].most_common(10),
            "user_agents": e["agents"].most_common(5), "regions": e["regions"].most_common(),
            "access_keys": sorted(e["access_keys"]),
        })
    risky.sort(key=lambda r: r["time"] or "")
    return {"record_count": len(records), "identities": identities, "high_risk_events": risky}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+")
    args = ap.parse_args(argv)
    records = []
    for name in args.files:
        records += load_records(Path(name))
    json.dump(summarize(records), sys.stdout, indent=2, default=str)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
