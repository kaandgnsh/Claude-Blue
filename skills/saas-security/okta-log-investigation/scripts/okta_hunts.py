#!/usr/bin/env python3
"""Run the Okta System Log hunts from SKILL.md over an exported log (stdlib only).

Input: JSON array as returned by /api/v1/logs (pages concatenated are fine) or JSON lines.
Hunts:
  factor-reset-then-new-ip  factor reset/deactivate for a user, then a sign-in by that user within
                            --reset-hours from an IP not seen for that user before the reset
  push-fatigue              >= --push-count push sends/denies for one user inside --push-minutes,
                            followed by a successful MFA within that window
  session-multi-ip          one externalSessionId used from more than one ASN (or IP when ASN missing)
  rogue-idp                 identity provider created/updated or IdP routing rule changed
  human-api-token           API token created by a User actor
  admin-grant               admin privilege grant or membership add to a group whose name contains "admin"
Output: JSON list of findings. Exit 0.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

RESET_EVENTS = {"user.mfa.factor.reset_all", "user.mfa.factor.deactivate"}
SIGNIN_EVENTS = {"user.session.start", "user.authentication.sso", "user.authentication.auth_via_mfa"}
PUSH_EVENTS = {"system.push.send_factor_verify_push", "user.mfa.okta_verify.deny_push"}
IDP_EVENTS = {"system.idp.lifecycle.create", "system.idp.lifecycle.update", "system.idp.lifecycle.activate"}


def load(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8").strip()
    if text.startswith("["):
        events = json.loads(text)
    else:
        events = [json.loads(line) for line in text.splitlines() if line.strip()]
    for e in events:
        e["_t"] = datetime.fromisoformat(e["published"].replace("Z", "+00:00"))
    return sorted(events, key=lambda e: e["_t"])


def g(event, *keys):
    cur = event
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def targets(event, ttype=None):
    return [t for t in event.get("target") or [] if ttype is None or t.get("type") == ttype]


def hunt(events, reset_hours=24, push_count=5, push_minutes=10):
    findings = []

    def add(kind, event, user, detail):
        findings.append({"hunt": kind, "published": event["published"], "user": user,
                         "ip": g(event, "client", "ipAddress"), "eventType": event["eventType"], "detail": detail})

    seen_ips = defaultdict(set)
    resets = {}  # user -> (time, ips known at reset)
    pushes = defaultdict(list)
    sessions = defaultdict(set)

    for e in events:
        etype, actor = e["eventType"], g(e, "actor", "alternateId")
        ok = g(e, "outcome", "result") == "SUCCESS"
        ip = g(e, "client", "ipAddress")

        if etype in RESET_EVENTS:
            for t in targets(e, "User") or [{"alternateId": actor}]:
                user = t.get("alternateId")
                resets[user] = (e["_t"], set(seen_ips[user]))
        if etype in SIGNIN_EVENTS and ok and actor:
            if actor in resets:
                when, known = resets[actor]
                if e["_t"] - when <= timedelta(hours=reset_hours) and ip and ip not in known:
                    add("factor-reset-then-new-ip", e, actor,
                        f"sign-in {int((e['_t'] - when).total_seconds() // 60)} min after factor reset from new IP {ip}")
                    resets.pop(actor)
            if ip:
                seen_ips[actor].add(ip)

        if etype in PUSH_EVENTS:
            user = actor if etype == "user.mfa.okta_verify.deny_push" else \
                (targets(e, "User") or [{"alternateId": actor}])[0].get("alternateId")
            pushes[user].append(e["_t"])
        if etype == "user.authentication.auth_via_mfa" and ok:
            window = [t for t in pushes.get(actor, []) if e["_t"] - t <= timedelta(minutes=push_minutes)]
            if len(window) >= push_count:
                add("push-fatigue", e, actor, f"MFA success after {len(window)} pushes/denies in {push_minutes} min")
                pushes[actor] = []

        session = g(e, "authenticationContext", "externalSessionId")
        if session and session != "unknown" and actor:
            asn = g(e, "securityContext", "asNumber")
            key = f"AS{asn}" if asn else ip
            if key:
                before = set(sessions[session])
                sessions[session].add(key)
                if before and key not in before:
                    add("session-multi-ip", e, actor,
                        f"session {session} now seen from {sorted(sessions[session])}")

        if etype in IDP_EVENTS or (etype == "policy.rule.update" and
                                   any("IdP" in (t.get("displayName") or "") or t.get("type") == "IdpDiscoveryRule"
                                       for t in targets(e))):
            add("rogue-idp", e, actor, f"{etype} on {[t.get('displayName') for t in targets(e)]}")
        if etype == "system.api_token.create" and g(e, "actor", "type") == "User":
            add("human-api-token", e, actor, f"token {[t.get('displayName') for t in targets(e)]}")
        if etype == "user.account.privilege.grant" or (
                etype == "group.user_membership.add" and
                any("admin" in (t.get("displayName") or "").lower() for t in targets(e, "UserGroup"))):
            add("admin-grant", e, actor,
                f"to {[t.get('alternateId') for t in targets(e, 'User')]} via {[t.get('displayName') for t in targets(e) if t.get('type') != 'User']}")
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfile", type=Path)
    ap.add_argument("--reset-hours", type=float, default=24)
    ap.add_argument("--push-count", type=int, default=5)
    ap.add_argument("--push-minutes", type=float, default=10)
    args = ap.parse_args(argv)
    findings = hunt(load(args.logfile), args.reset_hours, args.push_count, args.push_minutes)
    json.dump(findings, sys.stdout, indent=2)
    print()
    print(f"findings={len(findings)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
