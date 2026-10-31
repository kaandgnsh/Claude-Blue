#!/usr/bin/env python3
"""Functional test of a generated nftables ruleset with real traffic in isolated network namespaces.

Needs no root: re-executes itself under `unshare -rn` (user + network namespace). The host's
firewall and network are never touched. For each probe source the harness creates a client
namespace connected by a veth pair, starts TCP/UDP listeners on every policy port in the server
namespace, loads the ruleset there, and checks that exactly the expected connections succeed.

Usage: netns_test.py policy.json firewall.nft [--source 10.20.0.5 --source 198.51.100.7 ...]
Exit codes: 0 all probes matched the policy, 1 mismatch, 2 environment/setup error.
"""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import nft_policy  # noqa: E402

SERVER_V4 = "192.0.2.1"
UNLISTED_PORT = 9  # discard: not allowed by any sane policy; must always be blocked


def sh(*cmd, ns=None, check=True):
    if ns is not None:
        cmd = ("nsenter", "-t", str(ns), "-n", *cmd)
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def default_sources(policy):
    sources = []
    for rule in policy["inbound"]:
        for net in rule["v4"] or []:
            sources.append(str(net.network_address + (1 if net.num_addresses > 2 else 0)))
    sources.append("203.0.113.77")  # TEST-NET-3: outside every allowlist unless a rule is 'any'
    return sorted(set(sources), key=lambda ip: ipaddress.ip_address(ip))


def expected(policy, source, proto, port):
    addr = ipaddress.ip_address(source)
    for rule in policy["inbound"]:
        if rule["proto"] != proto or not any(lo <= port <= hi for lo, hi in rule["ports"]):
            continue
        if rule["any"] or any(addr in net for net in (rule["v4"] or [])):
            return True
    return False


def listen(proto, port, stop):
    kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    s = socket.socket(socket.AF_INET, kind)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((SERVER_V4, port))
    s.settimeout(0.2)
    if proto == "tcp":
        s.listen(16)
    while not stop.is_set():
        try:
            if proto == "tcp":
                conn, _ = s.accept()
                conn.close()
            else:
                data, peer = s.recvfrom(64)
                s.sendto(b"ok:" + data, peer)
        except OSError:
            continue
    s.close()


PROBE = r"""
import socket, sys
proto, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    if proto == "tcp":
        socket.create_connection((host, port), timeout=1.5).close()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1.5)
        s.sendto(b"x", (host, port)); s.recvfrom(64)
    print("open")
except OSError:
    print("blocked")
"""


def run_inside(policy_path, ruleset_path, sources):
    policy, _ = nft_policy.normalize(json.load(open(policy_path)))
    sources = sources or default_sources(policy)
    probes = sorted({(r["proto"], lo) for r in policy["inbound"] for lo, _ in r["ports"]} |
                    {(r["proto"], hi) for r in policy["inbound"] for _, hi in r["ports"]} | {("tcp", UNLISTED_PORT)})
    sh("ip", "link", "set", "lo", "up")
    children = []
    try:
        for i, src in enumerate(sources):
            child = subprocess.Popen(["unshare", "-n", "sleep", "600"])
            children.append(child)
            time.sleep(0.2)
            srv, cli = f"cbs{i}", f"cbc{i}"
            sh("ip", "link", "add", "name", srv, "type", "veth", "peer", "name", cli)
            sh("ip", "link", "set", cli, "netns", str(child.pid))
            if i == 0:
                sh("ip", "addr", "add", f"{SERVER_V4}/32", "dev", "lo")
            sh("ip", "link", "set", srv, "up")
            sh("ip", "route", "add", f"{src}/32", "dev", srv)
            sh("ip", "link", "set", "lo", "up", ns=child.pid)
            sh("ip", "addr", "add", f"{src}/32", "dev", cli, ns=child.pid)
            sh("ip", "link", "set", cli, "up", ns=child.pid)
            sh("ip", "route", "add", f"{SERVER_V4}/32", "dev", cli, ns=child.pid)
            sh("sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0", check=False)
        stop = threading.Event()
        threads = [threading.Thread(target=listen, args=(p, port, stop), daemon=True) for p, port in probes]
        for t in threads:
            t.start()
        time.sleep(0.3)
        result = sh("nft", "-f", ruleset_path, check=False)
        if result.returncode != 0:
            print(f"ERROR: nft failed to load ruleset:\n{result.stderr}", file=sys.stderr)
            return 2
        failures = 0
        for src, child in zip(sources, children):
            for proto, port in probes:
                want = expected(policy, src, proto, port)
                got = sh(sys.executable, "-c", PROBE, proto, SERVER_V4, str(port), ns=child.pid).stdout.strip() == "open"
                status = "ok  " if got == want else "FAIL"
                failures += got != want
                print(f"{status} {src:>15} -> {proto}/{port:<5} expected={'open' if want else 'blocked':7} got={'open' if got else 'blocked'}")
        stop.set()
        print(f"probes={len(sources) * len(probes)} failures={failures}")
        return 1 if failures else 0
    finally:
        for child in children:
            child.kill()


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    sources = []
    while "--source" in argv:
        i = argv.index("--source")
        sources.append(argv[i + 1])
        del argv[i:i + 2]
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    if os.environ.get("CB_NETNS_INNER") != "1":
        for tool in ("unshare", "nsenter", "nft", "ip"):
            if not shutil.which(tool):
                print(f"ERROR: required tool {tool!r} not found", file=sys.stderr)
                return 2
        env = dict(os.environ, CB_NETNS_INNER="1")
        cmd = ["unshare", "-rn", sys.executable, os.path.abspath(__file__), *map(os.path.abspath, argv)]
        for src in sources:
            cmd += ["--source", src]
        return subprocess.run(cmd, env=env).returncode
    return run_inside(argv[0], argv[1], sources)


if __name__ == "__main__":
    sys.exit(main())
