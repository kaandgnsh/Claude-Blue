#!/usr/bin/env python3
"""Generate a validated nftables host firewall from a JSON policy (stdlib only).

The output manages exactly one table (`inet <table>`, default `cb_filter`) and replaces it
atomically, so other tables (Docker, libvirt, firewalld) are never flushed.

Usage:
  nft_policy.py policy.json -o firewall.nft     # validate + generate
  nft_policy.py policy.json --explain           # human-readable summary
  nft_policy.py --example > policy.json         # starter policy
Exit codes: 0 ok, 1 warnings with --strict, 2 invalid policy.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys

NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
RATE_RE = re.compile(r"^(\d+)/(second|minute|hour|day)$")
PORT_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")
SENSITIVE_PORTS = {22, 23, 445, 1433, 2375, 2376, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 10250, 11211, 27017}
EXAMPLE = {
    "name": "web-server",
    "table": "cb_filter",
    "default_output": "accept",
    "allow_ping": True,
    "log_drops": True,
    "inbound": [
        {"name": "ssh", "proto": "tcp", "ports": [22], "sources": ["10.20.0.0/24", "2001:db8:20::/64"],
         "rate_limit": "10/minute", "management": True},
        {"name": "web", "proto": "tcp", "ports": [80, 443], "sources": ["any"]},
        {"name": "node_exporter", "proto": "tcp", "ports": [9100], "sources": ["10.20.5.10"]},
    ],
    "outbound": [],
}


class PolicyError(ValueError):
    pass


def parse_ports(raw, where):
    if not isinstance(raw, list) or not raw:
        raise PolicyError(f"{where}: 'ports' must be a non-empty list")
    out = []
    for item in raw:
        m = PORT_RE.fullmatch(str(item))
        if not m:
            raise PolicyError(f"{where}: invalid port {item!r} (use 443 or '8000-8100')")
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (1 <= lo <= hi <= 65535):
            raise PolicyError(f"{where}: port {item!r} out of range 1-65535")
        out.append((lo, hi))
    return sorted(set(out))


def parse_addresses(raw, where, key):
    if not isinstance(raw, list) or not raw:
        raise PolicyError(f"{where}: '{key}' must be a non-empty list (use [\"any\"] for everyone)")
    if "any" in raw:
        if len(raw) > 1:
            raise PolicyError(f"{where}: 'any' cannot be combined with other {key}")
        return None, None
    v4, v6 = [], []
    for item in raw:
        try:
            net = ipaddress.ip_network(str(item), strict=False)
        except ValueError as exc:
            raise PolicyError(f"{where}: invalid address {item!r}: {exc}") from None
        (v4 if net.version == 4 else v6).append(net)
    return sorted(set(v4)), sorted(set(v6))


def normalize(policy):
    if not isinstance(policy, dict):
        raise PolicyError("policy must be a JSON object")
    known = {"name", "table", "default_output", "allow_ping", "log_drops", "allow_no_management", "inbound", "outbound"}
    unknown = set(policy) - known
    if unknown:
        raise PolicyError(f"unknown top-level keys: {sorted(unknown)}")
    table = policy.get("table", "cb_filter")
    if not NAME_RE.fullmatch(table):
        raise PolicyError(f"invalid table name {table!r}")
    default_output = policy.get("default_output", "accept")
    if default_output not in ("accept", "drop"):
        raise PolicyError("default_output must be 'accept' or 'drop'")
    result = {"name": str(policy.get("name", "unnamed")), "table": table, "default_output": default_output,
              "allow_ping": bool(policy.get("allow_ping", True)), "log_drops": bool(policy.get("log_drops", True)),
              "inbound": [], "outbound": []}
    warnings = []
    seen = set()
    for direction, key in (("inbound", "sources"), ("outbound", "destinations")):
        for idx, rule in enumerate(policy.get(direction, []) or []):
            where = f"{direction}[{idx}]"
            if not isinstance(rule, dict):
                raise PolicyError(f"{where}: must be an object")
            allowed = {"name", "proto", "ports", key, "rate_limit", "management", "comment"}
            if set(rule) - allowed:
                raise PolicyError(f"{where}: unknown keys {sorted(set(rule) - allowed)}")
            name = rule.get("name", "")
            if not NAME_RE.fullmatch(name):
                raise PolicyError(f"{where}: name must match {NAME_RE.pattern}")
            if (direction, name) in seen:
                raise PolicyError(f"{where}: duplicate rule name {name!r}")
            seen.add((direction, name))
            proto = rule.get("proto")
            if proto not in ("tcp", "udp"):
                raise PolicyError(f"{where}: proto must be 'tcp' or 'udp'")
            ports = parse_ports(rule.get("ports"), where)
            v4, v6 = parse_addresses(rule.get(key), where, key)
            rate = rule.get("rate_limit")
            if rate is not None and not RATE_RE.fullmatch(str(rate)):
                raise PolicyError(f"{where}: rate_limit must look like '10/minute'")
            if direction == "outbound" and (rate or rule.get("management")):
                raise PolicyError(f"{where}: rate_limit/management apply to inbound rules only")
            entry = {"name": name, "proto": proto, "ports": ports, "v4": v4, "v6": v6, "any": v4 is None,
                     "rate_limit": rate, "management": bool(rule.get("management")), "comment": str(rule.get("comment", ""))}
            if direction == "inbound" and entry["any"]:
                exposed = sorted(p for lo, hi in ports for p in SENSITIVE_PORTS if lo <= p <= hi)
                if exposed:
                    warnings.append(f"{where} ({name}): sensitive port(s) {exposed} open to any source")
            if direction == "inbound" and entry["any"] and entry["management"]:
                warnings.append(f"{where} ({name}): management access allowed from any source; restrict to admin networks")
            result[direction].append(entry)
    if not any(r["management"] for r in result["inbound"]) and not policy.get("allow_no_management"):
        raise PolicyError("no inbound rule is marked \"management\": true — applying this would lock out remote "
                          "administration. Mark the admin rule (e.g. SSH from the admin network) or set "
                          "\"allow_no_management\": true if the host is managed only from the console.")
    if default_output == "drop" and not result["outbound"]:
        warnings.append("default_output is 'drop' with no outbound rules: DNS, NTP, package updates and log shipping will fail")
    return result, warnings


def fmt_ports(ports):
    return ", ".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in ports)


def fmt_nets(nets):
    return ", ".join(str(n) if n.num_addresses > 1 else str(n.network_address) for n in nets)


def render(policy, source_digest):
    t = policy["table"]
    sets, inbound, outbound = [], [], []
    for direction, chain, addr_kw in (("inbound", inbound, "saddr"), ("outbound", outbound, "daddr")):
        prefix = "in" if direction == "inbound" else "out"
        for r in policy[direction]:
            match = f"{r['proto']} dport {{ {fmt_ports(r['ports'])} }}"
            note = f'comment "{prefix}:{r["name"]}"'
            if r["any"]:
                families = [("", "")]
            else:
                families = []
                for fam, nets, ftype, kw in (("v4", r["v4"], "ipv4_addr", "ip"), ("v6", r["v6"], "ipv6_addr", "ip6")):
                    if nets:
                        set_name = f"{prefix}_{r['name']}_{fam}"
                        sets.append(f"\tset {set_name} {{\n\t\ttype {ftype}\n\t\tflags interval\n\t\tauto-merge\n"
                                    f"\t\telements = {{ {fmt_nets(nets)} }}\n\t}}")
                        families.append((kw, f"{kw} {addr_kw} @{set_name} "))
            for kw, addr in families:
                if r["rate_limit"]:
                    fams = [("ip", "ipv4_addr")] if kw == "ip" else [("ip6", "ipv6_addr")] if kw == "ip6" else [("ip", "ipv4_addr"), ("ip6", "ipv6_addr")]
                    for fkw, ftype in fams:
                        rl = f"{prefix}_{r['name']}_rl{'4' if fkw == 'ip' else '6'}"
                        if not any(s.startswith(f"\tset {rl} ") for s in sets):
                            sets.append(f"\tset {rl} {{\n\t\ttype {ftype}\n\t\tflags dynamic\n\t\ttimeout 10m\n\t}}")
                        fam_guard = "" if kw else f"meta nfproto {'ipv4' if fkw == 'ip' else 'ipv6'} "
                        chain.append(f"\t\t{fam_guard}{addr}{match} ct state new add @{rl} {{ {fkw} saddr limit rate over "
                                     f"{r['rate_limit']} burst 5 packets }} counter drop comment \"{prefix}:{r['name']}:ratelimit\"")
                chain.append(f"\t\t{addr}{match} counter accept {note}")
    lines = [
        "#!/usr/sbin/nft -f",
        f"# Generated by Claude-Blue host-firewall-build — policy \"{policy['name']}\" (sha256 {source_digest[:16]})",
        "# Replaces only this table; other tables (Docker, libvirt, firewalld) are untouched.",
        f"table inet {t}",
        f"delete table inet {t}",
        "",
        f"table inet {t} {{",
    ]
    lines += [*sets, ""] if sets else []
    lines += [
        "\tchain input {",
        "\t\ttype filter hook input priority filter; policy drop;",
        "\t\tct state invalid counter drop comment \"invalid\"",
        "\t\tct state established,related accept",
        "\t\tiif \"lo\" accept",
        "\t\tip saddr 127.0.0.0/8 counter drop comment \"spoofed loopback\"",
        "\t\tip6 saddr ::1 counter drop comment \"spoofed loopback\"",
        "\t\ticmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, "
        "nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept comment \"required ICMPv6\"",
        "\t\ticmp type { destination-unreachable, time-exceeded, parameter-problem } accept",
    ]
    if policy["allow_ping"]:
        lines += ["\t\ticmp type echo-request limit rate 10/second accept",
                  "\t\ticmpv6 type echo-request limit rate 10/second accept"]
    lines += inbound
    if policy["log_drops"]:
        lines.append(f"\t\tlimit rate 5/minute burst 10 packets log prefix \"{t}-in-drop: \" level info")
    lines += ["\t\tcounter comment \"default drop\"", "\t}", "",
              "\tchain forward {", "\t\ttype filter hook forward priority filter; policy drop;", "\t}", "",
              "\tchain output {", f"\t\ttype filter hook output priority filter; policy {policy['default_output']};"]
    if policy["default_output"] == "drop":
        lines += ["\t\tct state established,related accept", "\t\toif \"lo\" accept",
                  "\t\ticmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, packet-too-big } accept",
                  *outbound]
        if policy["log_drops"]:
            lines.append(f"\t\tlimit rate 5/minute burst 10 packets log prefix \"{t}-out-drop: \" level info")
        lines.append("\t\tcounter comment \"default drop\"")
    lines += ["\t}", "}", ""]
    return "\n".join(lines)


def explain(policy, warnings):
    out = [f"Policy {policy['name']!r} → table inet {policy['table']}",
           "input: default DROP; allows established/related, loopback, required ICMP" + (", ping" if policy["allow_ping"] else "")]
    for r in policy["inbound"]:
        src = "any" if r["any"] else fmt_nets(r["v4"] + r["v6"])
        extra = (f", rate limit {r['rate_limit']} per source" if r["rate_limit"] else "") + (" [management]" if r["management"] else "")
        out.append(f"  allow {r['proto']}/{fmt_ports(r['ports'])} from {src}{extra}  ({r['name']})")
    out.append(f"output: default {policy['default_output'].upper()}")
    for r in policy["outbound"]:
        dst = "any" if r["any"] else fmt_nets(r["v4"] + r["v6"])
        out.append(f"  allow {r['proto']}/{fmt_ports(r['ports'])} to {dst}  ({r['name']})")
    out.append("forward: DROP")
    out += [f"WARNING: {w}" for w in warnings]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("policy", nargs="?")
    ap.add_argument("-o", "--output")
    ap.add_argument("--explain", action="store_true")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    ap.add_argument("--example", action="store_true", help="print an example policy")
    args = ap.parse_args(argv)
    if args.example:
        print(json.dumps(EXAMPLE, indent=2))
        return 0
    if not args.policy:
        ap.error("policy file required")
    raw = open(args.policy, "rb").read()
    try:
        policy, warnings = normalize(json.loads(raw))
    except (PolicyError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)
    if args.explain:
        print(explain(policy, warnings))
    else:
        text = render(policy, hashlib.sha256(raw).hexdigest())
        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(text)
        else:
            sys.stdout.write(text)
    return 1 if (warnings and args.strict) else 0


if __name__ == "__main__":
    sys.exit(main())
