#!/usr/bin/env python3
"""Parse an .eml file into triage-ready JSON: sender alignment, auth results, Received hops,
URLs (defanged) and attachment hashes. Stdlib only; never opens attachments or URLs."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime

URL_RE = re.compile(r"""https?://[^\s"'<>\)\]]+""", re.I)
IP_RE = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc|arc)=(\w+)", re.I)


def defang(url: str) -> str:
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower().strip(">") if "@" in address else ""


def received_hops(msg):
    hops = []
    for header in reversed(msg.get_all("Received", [])):  # oldest first
        text = " ".join(str(header).split())
        hop = {"raw": text}
        m = re.search(r"\bfrom\s+(\S+)", text)
        if m:
            hop["from"] = m.group(1)
        m = re.search(r"\bby\s+(\S+)", text)
        if m:
            hop["by"] = m.group(1)
        hop["ips"] = IP_RE.findall(text.split(" by ")[0]) if " by " in text else IP_RE.findall(text)
        if ";" in text:
            try:
                hop["time"] = parsedate_to_datetime(text.rsplit(";", 1)[1].strip()).isoformat()
            except (TypeError, ValueError):
                pass
        hops.append(hop)
    return hops


def analyse(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    from_addrs = [a for _, a in getaddresses(msg.get_all("From", []))]
    reply_to = [a for _, a in getaddresses(msg.get_all("Reply-To", []))]
    return_path = (msg.get("Return-Path") or "").strip("<> ")
    from_domain = domain_of(from_addrs[0]) if from_addrs else ""
    auth = {}
    for header in msg.get_all("Authentication-Results", []):
        for mech, result in AUTH_RE.findall(str(header)):
            auth.setdefault(mech.lower(), result.lower())
    urls, attachments = set(), []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename or part.get_content_disposition() == "attachment":
            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
        elif part.get_content_maintype() == "text":
            urls.update(URL_RE.findall(payload.decode(part.get_content_charset() or "utf-8", "replace")))
    flags = []
    if return_path and domain_of(return_path) != from_domain:
        flags.append("return-path domain differs from From domain")
    if reply_to and domain_of(reply_to[0]) != from_domain:
        flags.append("reply-to domain differs from From domain")
    for mech in ("spf", "dkim", "dmarc"):
        if auth.get(mech) not in (None, "pass"):
            flags.append(f"{mech}={auth[mech]}")
    if "dmarc" not in auth:
        flags.append("no dmarc result recorded")
    return {
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "message_id": msg.get("Message-ID"),
        "from": from_addrs,
        "reply_to": reply_to,
        "return_path": return_path,
        "authentication_results": auth,
        "received_hops_oldest_first": received_hops(msg),
        "urls_defanged": sorted(defang(u) for u in urls),
        "attachments": attachments,
        "flags": flags,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("eml")
    args = ap.parse_args(argv)
    with open(args.eml, "rb") as handle:
        json.dump(analyse(handle.read()), sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
