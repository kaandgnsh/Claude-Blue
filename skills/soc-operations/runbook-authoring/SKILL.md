---
name: runbook-authoring
description: Write or review an operational SOC runbook for a specific alert type or response action, with trigger, prerequisites, decision points, exact queries/commands, rollback and success criteria. Use when creating a new runbook, converting tribal knowledge into steps, or reviewing whether an existing runbook is executable.
license: MIT
metadata:
  category: soc-operations
  version: "2.0.0"
  verification: documented
---

# Runbook Authoring

A runbook is executable at 03:00 by an analyst who has never seen the alert. Test it by having someone else follow it.

## Required structure

1. **Trigger** — exact rule names/IDs or conditions that invoke the runbook.
2. **Scope & authority** — who may execute which steps; which steps need approval.
3. **Prerequisites** — access/roles, tools, data sources and their retention.
4. **Triage steps** — numbered, each with the exact query/command, expected output, and how to interpret it.
5. **Decision points** — explicit branches: "If X → step 7; if Y → close as BTP with reason Z".
6. **Response actions** — command/console path, expected impact, rollback, verification.
7. **Escalation** — criteria and contacts (role-based, not personal names).
8. **Closure criteria** — what must be true to close; required reason codes.
9. **Maintenance** — owner, last tested date, review interval (≤12 months), change log.

## Writing rules

- One action per step; imperative verbs ("Run", "Record", "If").
- Put queries in code blocks with placeholders in `<ANGLE>` and a note of which fields to replace.
- State the expected result of every check ("returns 0 rows if benign").
- Prefer reversible actions first; mark irreversible steps with **IRREVERSIBLE** and require approval.
- Link to dependent runbooks instead of duplicating them.

## Review rubric

| Check | Pass condition |
|---|---|
| Executability | A peer followed it on a test case without asking questions |
| Accuracy | Every query ran against current schema in the last review cycle |
| Decision coverage | Every branch ends in close, escalate, or another runbook |
| Safety | Disruptive steps have approval, rollback, and verification |
| Currency | Owner and review date within interval |

## Output skeleton

```markdown
# Runbook: <alert/action>   Owner: <team>  Last tested: <date>
## Trigger
## Prerequisites
## Triage
1. Run: `<query>` — expect <>; if <> go to 4
## Response
## Escalation
## Closure
## Change log
```

## Related skills

`alert-triage`, `escalation-decision`, `incident-report-writing`, `case-documentation`

## References

- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- CISA Incident & Vulnerability Response Playbooks: https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks
