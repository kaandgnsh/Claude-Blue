#!/usr/bin/env python3
"""First-pass triage of Zeek logs, TSV (with #fields header) or JSON lines, stdlib only.

Reads conn, dns, http, ssl, files and dce_rpc logs (type taken from the #path header,
the `_path` field, or the file name) and reports:
  long-connection      conn duration > --long-seconds (default 3600)
  large-upload         orig_bytes > --upload-bytes to a non-private address, orig >> resp
  scan-like            one source with S0/REJ connections to > --scan-hosts distinct hosts
  dns-tunnel-like      queries with a label > 50 chars or high-entropy long labels
  rare-user-agent      user agents seen from at most --rare sources
  invalid-cert         ssl validation_status present and not "ok"
  executable-transfer  files.log mime type application/x-dosexec (or ELF / Mach-O)
  remote-service       dce_rpc svcctl Create* operations (PsExec-like)
  dcsync               dce_rpc drsuapi DRSGetNCChanges from a non-DC (see --dc)
Output: JSON list of findings sorted by severity. Exit 0.
"""
from __future__ import annotations

import argparse
import gzip
import ipaddress
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

SEVERITY = {"dcsync": 4, "remote-service": 3, "executable-transfer": 3, "large-upload": 3, "dns-tunnel-like": 2,
            "invalid-cert": 2, "long-connection": 2, "scan-like": 2, "rare-user-agent": 1}
EXEC_MIME = {"application/x-dosexec", "application/x-executable", "application/x-elf", "application/x-mach-o-executable"}


def open_text(path: Path):
    return gzip.open(path, "rt", encoding="utf-8", errors="replace") if path.suffix == ".gz" else \
        path.open(encoding="utf-8", errors="replace")


def read_log(path: Path):
    """Yield (log_type, record dict) from a Zeek TSV or JSON log."""
    log_type = path.name.split(".")[0]
    fields, sep, unset = None, "\t", {"-", "(empty)"}
    with open_text(path) as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("{"):
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                yield rec.get("_path", log_type), rec
                continue
            if line.startswith("#separator"):
                sep = line.split(" ", 1)[1].encode().decode("unicode_escape")
            elif line.startswith("#path"):
                log_type = line.split(sep)[1]
            elif line.startswith("#fields"):
                fields = line.split(sep)[1:]
            elif line.startswith("#"):
                continue
            elif fields:
                values = line.split(sep)
                yield log_type, {k: (None if v in unset else v) for k, v in zip(fields, values)}


def num(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "224.0.0.0/4", "255.255.255.255/32", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")]


def is_public(addr) -> bool:
    """True for addresses outside RFC 1918/6598, loopback, link-local and multicast ranges."""
    try:
        ip = ipaddress.ip_address(str(addr))
    except ValueError:
        return False
    return not any(ip.version == net.version and ip in net for net in INTERNAL_NETS)


def entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values()) if text else 0.0


def triage(paths, long_seconds=3600, upload_bytes=50_000_000, scan_hosts=50, rare=1, dcs=()):
    findings = []
    scan = defaultdict(set)
    agents = defaultdict(set)

    def add(kind, rec, detail):
        findings.append({"type": kind, "severity": SEVERITY[kind], "ts": rec.get("ts"), "uid": rec.get("uid"),
                         "src": rec.get("id.orig_h"), "dst": rec.get("id.resp_h"), "detail": detail})

    for path in paths:
        for log_type, rec in read_log(path):
            if log_type == "conn":
                duration, ob, rb = num(rec.get("duration")), num(rec.get("orig_bytes")), num(rec.get("resp_bytes"))
                if duration > long_seconds:
                    add("long-connection", rec, f"{duration:.0f}s to {rec.get('id.resp_h')}:{rec.get('id.resp_p')}")
                if ob > upload_bytes and is_public(rec.get("id.resp_h")) and ob > 10 * max(rb, 1):
                    add("large-upload", rec, f"{int(ob)} bytes out vs {int(rb)} in")
                if rec.get("conn_state") in ("S0", "REJ"):
                    scan[rec.get("id.orig_h")].add(rec.get("id.resp_h"))
            elif log_type == "dns":
                query = rec.get("query") or ""
                labels = query.split(".")
                longest = max(labels, key=len) if labels else ""
                if len(longest) > 50 or (len(longest) >= 25 and entropy(longest) > 4.0):
                    add("dns-tunnel-like", rec, f"label of {len(longest)} chars, entropy {entropy(longest):.2f}: {query[:120]}")
            elif log_type == "http":
                if rec.get("user_agent"):
                    agents[rec["user_agent"]].add(rec.get("id.orig_h"))
            elif log_type == "ssl":
                status = rec.get("validation_status")
                if status and status != "ok":
                    add("invalid-cert", rec, f"{rec.get('server_name')}: {status}")
            elif log_type == "files":
                if rec.get("mime_type") in EXEC_MIME:
                    tx, rx = rec.get("tx_hosts"), rec.get("rx_hosts")
                    rec = dict(rec, **{"id.orig_h": tx[0] if isinstance(tx, list) and tx else tx,
                                       "id.resp_h": rx[0] if isinstance(rx, list) and rx else rx})
                    add("executable-transfer", rec, f"{rec.get('mime_type')} sha256={rec.get('sha256')} name={rec.get('filename')}")
            elif log_type == "dce_rpc":
                endpoint, op = rec.get("endpoint") or "", rec.get("operation") or ""
                if endpoint == "svcctl" and "Create" in op:
                    add("remote-service", rec, op)
                if endpoint == "drsuapi" and op == "DRSGetNCChanges" and rec.get("id.orig_h") not in dcs:
                    add("dcsync", rec, "replication request from a host not listed as a domain controller")

    for src, dsts in scan.items():
        if len(dsts) > scan_hosts:
            findings.append({"type": "scan-like", "severity": SEVERITY["scan-like"], "ts": None, "uid": None,
                             "src": src, "dst": None, "detail": f"S0/REJ to {len(dsts)} distinct hosts"})
    for agent, sources in agents.items():
        if len(sources) <= rare:
            findings.append({"type": "rare-user-agent", "severity": SEVERITY["rare-user-agent"], "ts": None, "uid": None,
                             "src": sorted(s for s in sources if s), "dst": None, "detail": agent[:200]})
    findings.sort(key=lambda f: (-f["severity"], f["type"], str(f["ts"])))
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="+", type=Path, help="Zeek log files (TSV or JSON, optionally .gz)")
    ap.add_argument("--long-seconds", type=float, default=3600)
    ap.add_argument("--upload-bytes", type=float, default=50_000_000)
    ap.add_argument("--scan-hosts", type=int, default=50)
    ap.add_argument("--rare", type=int, default=1, help="user agent is rare when seen from at most N sources")
    ap.add_argument("--dc", action="append", default=[], help="domain controller IP (repeatable)")
    args = ap.parse_args(argv)
    findings = triage(args.logs, args.long_seconds, args.upload_bytes, args.scan_hosts, args.rare, set(args.dc))
    json.dump(findings, sys.stdout, indent=2)
    print()
    counts = Counter(f["type"] for f in findings)
    print(" ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "no findings", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
