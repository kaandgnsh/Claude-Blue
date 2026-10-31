#!/usr/bin/env python3
"""Heuristic security audit of GitHub Actions workflow files (stdlib only, no YAML parser).

Flags: pull_request_target/workflow_run checking out untrusted code, script injection via
${{ github.event.* }} / head_ref in run blocks, actions not pinned to a full commit SHA,
missing or broad permissions, and self-hosted runners. Output: JSON list of findings.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SHA_PIN = re.compile(r"@[0-9a-f]{40}\b")
USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)")
UNTRUSTED_EXPR = re.compile(
    r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|discussion|pages|head_commit|commits|workflow_run)"
    r"[^}]*|github\.head_ref)\s*\}\}")
HEAD_CHECKOUT = re.compile(r"github\.event\.(pull_request\.head\.(sha|ref)|workflow_run\.head_(sha|branch))|github\.head_ref")


def audit_file(path: Path):
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    text = "\n".join(lines)
    findings = []

    def add(line_no, severity, rule, message):
        findings.append({"file": str(path), "line": line_no, "severity": severity, "rule": rule, "message": message})

    privileged_trigger = re.search(r"^\s*(pull_request_target|workflow_run)\s*:", text, re.M) or \
        re.search(r"^on:\s*\[?[^\n]*\b(pull_request_target|workflow_run)\b", text, re.M)
    if not re.search(r"^permissions\s*:", text, re.M):
        add(1, "medium", "missing-top-level-permissions",
            "No top-level 'permissions:'; GITHUB_TOKEN gets the repository default (possibly write-all). Set least privilege, e.g. 'permissions: contents: read'.")
    run_indent = None
    in_checkout = False
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if re.match(r"^permissions\s*:\s*write-all", stripped):
            add(number, "high", "write-all-permissions", "permissions: write-all grants every scope to GITHUB_TOKEN.")
        if re.match(r"^runs-on\s*:.*self-hosted", stripped):
            add(number, "info", "self-hosted-runner",
                "Self-hosted runner: never use on public repositories that run untrusted PRs; ensure ephemeral, isolated runners.")
        if stripped.startswith("secrets: inherit"):
            add(number, "info", "secrets-inherit", "Reusable workflow receives all secrets; pass only those required.")
        m = USES.match(line)
        if m:
            ref = m.group(1)
            in_checkout = ref.startswith("actions/checkout@")
            if not ref.startswith(("./", "docker://")) and "@" in ref and not SHA_PIN.search(ref):
                add(number, "medium", "unpinned-action",
                    f"'{ref}' is not pinned to a full-length commit SHA; tags can be moved (cf. tj-actions/changed-files 2025).")
        elif stripped.startswith("- ") or (stripped.startswith("name:") and indent <= 6):
            in_checkout = False
        if privileged_trigger and in_checkout and stripped.startswith("ref:") and HEAD_CHECKOUT.search(stripped):
            add(number, "critical", "privileged-untrusted-checkout",
                "pull_request_target/workflow_run checks out PR head code: untrusted code runs with secrets and a write token ('pwn request').")
        if run_indent is not None and stripped and indent <= run_indent:
            run_indent = None
        run_match = re.match(r"^(\s*)-?\s*run\s*:\s*(.*)$", line)
        if run_match:
            run_indent = indent
            body = run_match.group(2)
            if UNTRUSTED_EXPR.search(body):
                add(number, "high", "script-injection",
                    "Untrusted github.event/head_ref expression interpolated into a shell command; pass via env: and quote \"$VAR\".")
            continue
        if run_indent is not None and indent > run_indent and UNTRUSTED_EXPR.search(line):
            add(number, "high", "script-injection",
                "Untrusted github.event/head_ref expression interpolated into a shell command; pass via env: and quote \"$VAR\".")
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", default=[".github/workflows"], help="workflow files or directories")
    ap.add_argument("--fail-on", choices=("info", "medium", "high", "critical"), default="high")
    args = ap.parse_args(argv)
    files = []
    for raw in args.paths:
        p = Path(raw)
        files += sorted(p.glob("*.y*ml")) if p.is_dir() else [p]
    findings = [f for path in files for f in audit_file(path)]
    json.dump(findings, sys.stdout, indent=2)
    print()
    order = ["info", "medium", "high", "critical"]
    threshold = order.index(args.fail_on)
    return 1 if any(order.index(f["severity"]) >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
