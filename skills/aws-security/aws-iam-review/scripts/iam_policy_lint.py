#!/usr/bin/env python3
"""Lint AWS IAM policy documents for risky grants (stdlib only).

Input: one or more JSON files containing a policy document ({"Version", "Statement"}), the output of
`aws iam get-policy-version` ({"PolicyVersion": {"Document": ...}}), or
`aws iam get-account-authorization-details` (all managed and inline policies are checked).
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from urllib.parse import unquote

# Actions that allow privilege escalation or broad compromise (non-exhaustive, from public research).
ESCALATION = [
    "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:AttachUserPolicy", "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy", "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy",
    "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy", "iam:PassRole", "sts:AssumeRole", "lambda:UpdateFunctionCode",
    "lambda:CreateFunction", "ec2:RunInstances", "glue:CreateDevEndpoint", "cloudformation:CreateStack",
    "ssm:SendCommand", "ssm:StartSession", "kms:Decrypt", "secretsmanager:GetSecretValue",
]
ORDER = ["low", "medium", "high", "critical"]


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def lint_document(doc, source):
    if isinstance(doc, str):
        doc = json.loads(unquote(doc))
    findings = []
    for idx, stmt in enumerate(as_list(doc.get("Statement"))):
        if stmt.get("Effect") != "Allow":
            continue
        sid = stmt.get("Sid", f"#{idx}")
        actions = as_list(stmt.get("Action"))
        resources = as_list(stmt.get("Resource"))
        has_condition = bool(stmt.get("Condition"))
        where = f"{source} statement {sid}"

        def add(sev, rule, msg):
            if has_condition and sev in ("high", "critical"):
                sev = ORDER[ORDER.index(sev) - 1]
                msg += " (conditioned — verify the condition actually constrains it)"
            findings.append({"severity": sev, "rule": rule, "where": where, "message": msg})

        if "NotAction" in stmt:
            add("high", "allow-notaction", "Allow with NotAction grants everything except the listed actions.")
        if "NotResource" in stmt:
            add("medium", "allow-notresource", "Allow with NotResource applies to all other resources.")
        if any(a == "*" for a in actions):
            add("critical", "admin-wildcard", "Action '*' — full administrator access.")
        for a in actions:
            if a != "*" and a.endswith(":*"):
                add("high", "service-wildcard", f"Service-wide wildcard action '{a}'.")
        escalations = sorted({e for e in ESCALATION for a in actions if a != "*" and matches(a, e)})
        if escalations:
            sev = "high" if "*" in resources else "medium"
            add(sev, "privilege-escalation-actions",
                f"Grants escalation-capable actions {escalations} on resources {resources}.")
        if "*" in resources and actions and all(not a.lower().startswith(("iam:get", "iam:list")) for a in actions) \
                and not any(a == "*" for a in actions):
            add("low", "resource-wildcard", "Resource '*' — consider scoping to specific ARNs.")
        principal = stmt.get("Principal")
        if principal == "*" or (isinstance(principal, dict) and "*" in as_list(principal.get("AWS"))):
            add("critical" if not has_condition else "high", "public-principal",
                "Resource/trust policy allows Principal '*' (anyone).")
    return findings


def documents(data, source):
    if "Statement" in data:
        yield source, data
    elif "PolicyVersion" in data:
        yield source, data["PolicyVersion"]["Document"]
    elif "Policies" in data or "UserDetailList" in data or "RoleDetailList" in data:
        for pol in data.get("Policies", []):
            for ver in pol.get("PolicyVersionList", []):
                if ver.get("IsDefaultVersion"):
                    yield f"managed:{pol.get('Arn')}", ver["Document"]
        for kind, key in (("user", "UserDetailList"), ("role", "RoleDetailList"), ("group", "GroupDetailList")):
            for ent in data.get(key, []):
                for inline in ent.get(f"{kind.capitalize()}PolicyList", []):
                    yield f"inline:{kind}/{ent.get(kind.capitalize() + 'Name')}/{inline.get('PolicyName')}", inline["PolicyDocument"]
                if kind == "role" and ent.get("AssumeRolePolicyDocument"):
                    yield f"trust:role/{ent.get('RoleName')}", ent["AssumeRolePolicyDocument"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+")
    ap.add_argument("--min-severity", choices=ORDER, default="low")
    args = ap.parse_args(argv)
    findings = []
    for name in args.files:
        with open(name, encoding="utf-8") as handle:
            data = json.load(handle)
        for source, doc in documents(data, name):
            findings += lint_document(doc, source)
    threshold = ORDER.index(args.min_severity)
    findings = sorted((f for f in findings if ORDER.index(f["severity"]) >= threshold),
                      key=lambda f: -ORDER.index(f["severity"]))
    json.dump(findings, sys.stdout, indent=2)
    print()
    return 1 if any(f["severity"] == "critical" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
