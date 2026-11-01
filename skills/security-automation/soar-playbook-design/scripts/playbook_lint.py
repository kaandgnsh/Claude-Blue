#!/usr/bin/env python3
"""Lint a SOAR playbook described as a vendor-neutral JSON step graph (stdlib only).

Playbook shape (see SKILL.md for the full contract):
  {"name": "...", "owner": "...", "kill_switch": "...", "start": "<step id>",
   "steps": {"<id>": {"type": "query|enrich|decision|action|notify|wait|end", "next": "<id>",
                      "branches": {"<condition>": "<id>"}, "default": "<id>",
                      "action": "isolate_host", "destructive": true, "approval": "<role>",
                      "rollback": "<id or procedure>", "timeout_s": 300, "max_iterations": 3, ...}}}

Checks: dangling references, unreachable steps, paths that never reach an `end` step, loops
without max_iterations, decisions without a default branch, disruptive actions without approval,
rollback or timeout (also when the action name looks disruptive but `destructive` is unset),
missing owner/kill switch, and literal credentials in step parameters.
Output: JSON list of findings; exit 1 when a finding reaches --fail-on.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

STEP_TYPES = {"query", "enrich", "decision", "action", "notify", "wait", "end"}
DISRUPTIVE_VERBS = re.compile(
    r"(isolat|quarantin|disable|delete|remove|block|revoke|reset|kill|terminat|suspend|lock|wipe|rotate|purge|shutdown)",
    re.I)
SECRET_KEY = re.compile(r"(api[_-]?key|token|secret|password|passwd|bearer|client[_-]?secret)", re.I)
SECRET_REF = re.compile(r"^(\{\{.*\}\}|\$\{.*\}|vault:|secret:|env:|arn:aws:secretsmanager:|@Microsoft\.KeyVault)", re.I)
SEVERITY_ORDER = ["info", "medium", "high", "critical"]


def successors(step: dict) -> list[str]:
    out = []
    if isinstance(step.get("next"), str):
        out.append(step["next"])
    for target in (step.get("branches") or {}).values():
        if isinstance(target, str):
            out.append(target)
    if isinstance(step.get("default"), str):
        out.append(step["default"])
    if isinstance(step.get("on_error"), str):
        out.append(step["on_error"])
    return out


def walk_secrets(value, path=""):
    if isinstance(value, dict):
        for key, inner in value.items():
            here = f"{path}.{key}" if path else key
            if isinstance(inner, str) and SECRET_KEY.search(key) and inner and not SECRET_REF.match(inner):
                yield here
            else:
                yield from walk_secrets(inner, here)
    elif isinstance(value, list):
        for i, inner in enumerate(value):
            yield from walk_secrets(inner, f"{path}[{i}]")


def lint(book: dict) -> list[dict]:
    findings: list[dict] = []

    def add(step, severity, rule, message):
        findings.append({"step": step, "severity": severity, "rule": rule, "message": message})

    steps = book.get("steps")
    if not isinstance(steps, dict) or not steps:
        add(None, "critical", "no-steps", "Playbook has no 'steps' mapping.")
        return findings
    if not book.get("owner"):
        add(None, "medium", "no-owner", "No 'owner'; failed runs and stale logic need an accountable team.")
    if not book.get("kill_switch"):
        add(None, "high", "no-kill-switch",
            "No 'kill_switch'; operators need a documented way to stop every running instance at once.")
    start = book.get("start")
    if start not in steps:
        add(None, "critical", "bad-start", f"'start' {start!r} is not a step id.")
        return findings

    for sid, step in steps.items():
        stype = step.get("type")
        if stype not in STEP_TYPES:
            add(sid, "high", "unknown-type", f"type {stype!r} is not one of {sorted(STEP_TYPES)}.")
        for target in successors(step):
            if target not in steps:
                add(sid, "critical", "dangling-reference", f"points to missing step {target!r}.")
        if stype == "end" and successors(step):
            add(sid, "medium", "end-has-successor", "an 'end' step must not continue to another step.")
        if stype not in ("end", None) and not successors(step):
            add(sid, "high", "dead-end", "step has no successor and is not an 'end' step; runs stop silently here.")
        if stype == "decision":
            if not step.get("branches"):
                add(sid, "high", "decision-without-branches", "decision has no branches.")
            if not step.get("default"):
                add(sid, "high", "decision-without-default",
                    "decision has no 'default' branch; unexpected values (null, new enum) leave the run stuck.")
        if stype in ("enrich", "action", "query") and not step.get("timeout_s"):
            add(sid, "medium", "no-timeout", "external call without 'timeout_s'; a hung connector stalls the queue.")
        if stype in ("enrich", "action") and not step.get("on_error"):
            add(sid, "info", "no-error-path", "no 'on_error' step; connector failures fall back to the platform default.")
        action_name = str(step.get("action", ""))
        disruptive = bool(step.get("destructive")) or (stype == "action" and DISRUPTIVE_VERBS.search(action_name))
        if stype == "action" and DISRUPTIVE_VERBS.search(action_name) and "destructive" not in step:
            add(sid, "medium", "unmarked-disruptive-action",
                f"action {action_name!r} looks disruptive but 'destructive' is not set; declare it explicitly.")
        if disruptive:
            if not step.get("approval") and not step.get("auto_approved_by"):
                add(sid, "critical", "disruptive-without-approval",
                    f"disruptive action {action_name!r} has no 'approval' role or documented 'auto_approved_by' policy.")
            if not step.get("rollback"):
                add(sid, "high", "disruptive-without-rollback", f"disruptive action {action_name!r} has no 'rollback'.")
            if not step.get("idempotency_key"):
                add(sid, "medium", "no-idempotency-key",
                    "disruptive action without 'idempotency_key'; retries can act twice (e.g. disable two accounts).")
            if not step.get("exclusions") and step.get("auto_approved_by"):
                add(sid, "high", "auto-action-without-exclusions",
                    "auto-approved disruptive action without 'exclusions' (crown-jewel assets, break-glass accounts).")
        for secret_path in walk_secrets(step.get("params", {})):
            add(sid, "critical", "inline-secret", f"params.{secret_path} holds a literal credential; reference a vault.")

    # reachability
    seen, stack = set(), [start]
    while stack:
        sid = stack.pop()
        if sid in seen or sid not in steps:
            continue
        seen.add(sid)
        stack.extend(successors(steps[sid]))
    for sid in steps:
        if sid not in seen:
            add(sid, "medium", "unreachable", "step is not reachable from 'start'.")

    # loops: a back edge must sit on a step that bounds iterations
    colour: dict[str, int] = {}

    def dfs(sid):
        colour[sid] = 1
        for nxt in successors(steps[sid]):
            if nxt not in steps:
                continue
            if colour.get(nxt) == 1:
                if not (steps[nxt].get("max_iterations") or steps[sid].get("max_iterations")):
                    add(sid, "high", "unbounded-loop",
                        f"loop {sid!r} -> {nxt!r} without 'max_iterations'; a stuck condition retries forever.")
            elif nxt not in colour:
                dfs(nxt)
        colour[sid] = 2

    sys.setrecursionlimit(max(1000, len(steps) * 4))
    dfs(start)

    # every reachable step must be able to reach an end
    can_end = {sid for sid, s in steps.items() if s.get("type") == "end"}
    changed = True
    while changed:
        changed = False
        for sid, step in steps.items():
            if sid not in can_end and any(n in can_end for n in successors(step)):
                can_end.add(sid)
                changed = True
    for sid in sorted(seen - can_end):
        add(sid, "high", "never-terminates", "no path from this step reaches an 'end' step.")
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("playbooks", nargs="+", type=Path, help="playbook JSON files")
    ap.add_argument("--fail-on", choices=SEVERITY_ORDER, default="high")
    args = ap.parse_args(argv)
    threshold = SEVERITY_ORDER.index(args.fail_on)
    worst = -1
    report = []
    for path in args.playbooks:
        try:
            book = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"{path}: cannot read playbook: {exc}", file=sys.stderr)
            return 2
        for finding in lint(book):
            finding["file"] = str(path)
            report.append(finding)
            worst = max(worst, SEVERITY_ORDER.index(finding["severity"]))
    json.dump(report, sys.stdout, indent=2)
    print()
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
