#!/usr/bin/env python3
"""Extract, refang/defang and de-duplicate IOCs from text (reports, emails, tickets). Stdlib only.

Outputs JSON grouped by type: ipv4, ipv6, domain, url, email, md5, sha1, sha256, cve.
Private/reserved IPs are reported separately (they are rarely useful as external IOCs).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys

REFANG = [
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]|\[at\]|\(at\)", re.I), "@"),
    (re.compile(r"\bhxxp", re.I), "http"),
    (re.compile(r"\bfxp", re.I), "ftp"),
]
PATTERNS = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\]\)]+", re.I),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "ipv6": re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I),
}
# Extensions that look like TLDs but are usually file names in reports.
FILE_LIKE = {"exe", "dll", "ps1", "bat", "vbs", "js", "hta", "doc", "docx", "docm", "xls", "xlsx", "xlsm",
             "pdf", "zip", "rar", "7z", "iso", "img", "lnk", "txt", "log", "dat", "bin", "tmp", "py", "sh", "php", "jsp", "aspx"}


def refang(text: str) -> str:
    for pattern, repl in REFANG:
        text = pattern.sub(repl, text)
    return text


def defang(value: str) -> str:
    value = re.sub(r"^http", "hxxp", value, flags=re.I)
    return value.replace(".", "[.]").replace("@", "[@]")


def extract(text: str) -> dict:
    text = refang(text)
    found = {k: set() for k in PATTERNS}
    for kind in ("url", "email", "sha256", "sha1", "md5", "cve", "ipv4", "ipv6"):
        for m in PATTERNS[kind].findall(text):
            found[kind].add(m.lower() if kind in ("sha256", "sha1", "md5", "ipv6") else m.upper() if kind == "cve" else m)
    hashes = found["sha256"] | found["sha1"]
    found["md5"] = {h for h in found["md5"] if not any(h in longer for longer in hashes)}
    found["sha1"] = {h for h in found["sha1"] if not any(h in longer for longer in found["sha256"])}
    for m in PATTERNS["domain"].findall(text):
        domain = m.lower().rstrip(".")
        if domain.rsplit(".", 1)[-1] in FILE_LIKE or PATTERNS["ipv4"].fullmatch(domain):
            continue
        found["domain"].add(domain)
    private = set()
    for ip in list(found["ipv4"] | found["ipv6"]):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            found["ipv6"].discard(ip)
            continue
        if not addr.is_global:
            private.add(ip)
    found["ipv4"] -= private
    found["ipv6"] -= private
    result = {k: sorted(v) for k, v in found.items() if v}
    if private:
        result["non_global_ip"] = sorted(private)
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?", help="input file (default stdin)")
    ap.add_argument("--defang", action="store_true", help="defang network IOCs in output")
    args = ap.parse_args(argv)
    text = open(args.file, encoding="utf-8", errors="replace").read() if args.file else sys.stdin.read()
    result = extract(text)
    if args.defang:
        for kind in ("url", "domain", "email", "ipv4"):
            if kind in result:
                result[kind] = [defang(v) for v in result[kind]]
    json.dump(result, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
