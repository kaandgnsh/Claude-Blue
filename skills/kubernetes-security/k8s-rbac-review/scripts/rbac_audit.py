#!/usr/bin/env python3
"""Find risky Kubernetes RBAC grants from `kubectl get roles,clusterroles,rolebindings,clusterrolebindings -A -o json`.

Stdlib only. Reports, per subject, the dangerous permissions it receives and through which binding.
"""
from __future__ import annotations

import argparse
import json
import sys

DANGEROUS = [
    # (resource, verbs, severity, reason)
    ("*", {"*"}, "critical", "wildcard resources and verbs (cluster-admin equivalent)"),
    ("secrets", {"get", "list", "watch", "*"}, "high", "can read secrets (tokens, credentials)"),
    ("pods/exec", {"create", "*"}, "high", "can exec into pods"),
    ("pods/attach", {"create", "*"}, "high", "can attach to pods"),
    ("pods", {"create", "*"}, "high", "can create pods (mount secrets/service accounts, hostPath if not blocked)"),
    ("nodes/proxy", {"get", "create", "*"}, "high", "kubelet API access via nodes/proxy (command execution)"),
    ("serviceaccounts/token", {"create", "*"}, "high", "can mint service account tokens"),
    ("roles", {"escalate", "bind", "*"}, "critical", "can escalate/bind roles (privilege escalation)"),
    ("clusterroles", {"escalate", "bind", "*"}, "critical", "can escalate/bind cluster roles"),
    ("rolebindings", {"create", "update", "patch", "*"}, "high", "can create role bindings"),
    ("clusterrolebindings", {"create", "update", "patch", "*"}, "critical", "can create cluster role bindings"),
    ("users", {"impersonate", "*"}, "critical", "can impersonate users"),
    ("groups", {"impersonate", "*"}, "critical", "can impersonate groups"),
    ("serviceaccounts", {"impersonate", "*"}, "critical", "can impersonate service accounts"),
    ("certificatesigningrequests/approval", {"update", "patch", "*"}, "high", "can approve CSRs (mint client certs)"),
    ("mutatingwebhookconfigurations", {"create", "update", "patch", "*"}, "high", "can install mutating webhooks"),
    ("validatingwebhookconfigurations", {"create", "update", "patch", "delete", "*"}, "high", "can alter validating webhooks"),
    ("persistentvolumes", {"create", "*"}, "medium", "can create PVs (hostPath volumes)"),
]
BROAD_GROUPS = {"system:anonymous", "system:unauthenticated", "system:authenticated"}
ORDER = ["medium", "high", "critical"]


def rule_findings(rules):
    out = []
    for rule in rules or []:
        resources = set(rule.get("resources", []))
        verbs = set(rule.get("verbs", []))
        for resource, risky_verbs, severity, reason in DANGEROUS:
            res_match = resource in resources or "*" in resources
            if resource == "*":
                res_match = "*" in resources
            if res_match and verbs & risky_verbs:
                out.append((severity, resource, sorted(verbs & risky_verbs), reason))
    return out


def analyse(items):
    roles = {}
    for item in items:
        kind = item.get("kind")
        if kind in ("Role", "ClusterRole"):
            meta = item.get("metadata", {})
            key = (kind, meta.get("namespace", ""), meta.get("name"))
            roles[key] = item.get("rules", [])
    findings = []
    for item in items:
        kind = item.get("kind")
        if kind not in ("RoleBinding", "ClusterRoleBinding"):
            continue
        meta = item.get("metadata", {})
        ref = item.get("roleRef", {})
        ns = meta.get("namespace", "") if kind == "RoleBinding" else ""
        role_key = (ref.get("kind"), ns if ref.get("kind") == "Role" else "", ref.get("name"))
        rules = roles.get(role_key, [])
        risks = rule_findings(rules)
        if ref.get("name") == "cluster-admin":
            risks.append(("critical", "*", ["*"], "bound to cluster-admin"))
        for subject in item.get("subjects") or []:
            name = subject.get("name", "")
            if name.startswith("system:") and name not in BROAD_GROUPS and subject.get("kind") != "ServiceAccount":
                continue  # built-in control-plane identities
            sev_boost = name in BROAD_GROUPS
            for severity, resource, verbs, reason in risks:
                if sev_boost:
                    severity, reason = "critical", reason + f" — granted to broad group {name}"
                findings.append({
                    "severity": severity,
                    "subject": f"{subject.get('kind')}:{subject.get('namespace', '') + '/' if subject.get('namespace') else ''}{name}",
                    "binding": f"{kind}/{ns + '/' if ns else ''}{meta.get('name')}",
                    "role": f"{ref.get('kind')}/{ref.get('name')}",
                    "scope": "cluster" if kind == "ClusterRoleBinding" else f"namespace {ns}",
                    "resource": resource,
                    "verbs": verbs,
                    "reason": reason,
                })
    findings.sort(key=lambda f: (-ORDER.index(f["severity"]), f["subject"]))
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("json_file", help="output of kubectl get ... -o json (a List)")
    ap.add_argument("--min-severity", choices=ORDER, default="medium")
    args = ap.parse_args(argv)
    with open(args.json_file, encoding="utf-8") as handle:
        data = json.load(handle)
    items = data.get("items", data if isinstance(data, list) else [])
    threshold = ORDER.index(args.min_severity)
    findings = [f for f in analyse(items) if ORDER.index(f["severity"]) >= threshold]
    json.dump(findings, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
