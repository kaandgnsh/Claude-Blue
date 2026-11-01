#!/usr/bin/env python3
"""Rebuild tools/data/attack-enterprise.json from MITRE's attack-stix-data (stdlib only).

  python3 tools/refresh_attack.py                 # download the current Enterprise bundle and rewrite the snapshot
  python3 tools/refresh_attack.py --check         # exit 1 if the snapshot is behind upstream (no write)
  python3 tools/refresh_attack.py --input bundle.json

Keeps only active objects: revoked or deprecated techniques drop out, so `validate` then flags skills
that still cite them. Run `python3 tools/claude_blue.py validate` after a refresh and fix what it reports.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

URL = "https://github.com/mitre-attack/attack-stix-data/raw/refs/heads/master/enterprise-attack/enterprise-attack.json"
SNAPSHOT = Path(__file__).resolve().parent / "data" / "attack-enterprise.json"


def build(bundle: dict, source: str) -> dict:
    objects = bundle.get("objects", [])
    active = [o for o in objects if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    version = next((o.get("x_mitre_version") for o in objects if o.get("type") == "x-mitre-collection"), None)
    if not version:
        raise SystemExit("bundle has no x-mitre-collection object with x_mitre_version")
    tactics = sorted({o["x_mitre_shortname"] for o in active if o.get("type") == "x-mitre-tactic"})
    techniques, technique_tactics = {}, {}
    for obj in active:
        if obj.get("type") != "attack-pattern":
            continue
        ref = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ref or not ref.get("external_id", "").startswith("T"):
            continue
        tid = ref["external_id"]
        techniques[tid] = obj.get("name", "")
        phases = [p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        technique_tactics[tid] = list(dict.fromkeys(phases))  # STIX order, duplicates removed
    return {
        "source": source,
        "attack_version": str(version),
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
        "technique_tactics": dict(sorted(technique_tactics.items())),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", type=Path, help="local STIX bundle instead of downloading")
    ap.add_argument("--output", type=Path, default=SNAPSHOT)
    ap.add_argument("--check", action="store_true", help="only report whether the snapshot is current")
    args = ap.parse_args(argv)

    if args.input:
        bundle, source = json.loads(args.input.read_text(encoding="utf-8")), URL
    else:
        with urllib.request.urlopen(urllib.request.Request(URL, headers={"User-Agent": "claude-blue-attack-refresh"}),
                                    timeout=120) as resp:
            bundle, source = json.load(resp), URL
    fresh = build(bundle, source)
    current = json.loads(args.output.read_text(encoding="utf-8")) if args.output.is_file() else {}
    old_ids, new_ids = set(current.get("techniques", {})), set(fresh["techniques"])
    print(f"ATT&CK {current.get('attack_version', 'none')} -> {fresh['attack_version']}: "
          f"{len(new_ids - old_ids)} techniques added, {len(old_ids - new_ids)} removed (revoked/deprecated)")
    for tid in sorted(old_ids - new_ids):
        print(f"  removed: {tid} {current['techniques'][tid]}")
    if args.check:
        return 0 if fresh == current else 1
    args.output.write_text(json.dumps(fresh, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {args.output}; now run: python3 tools/claude_blue.py validate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
