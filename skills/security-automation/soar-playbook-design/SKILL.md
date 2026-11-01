---
name: soar-playbook-design
description: Design a SOAR or automation playbook as an explicit step graph with triggers, inputs, enrichment, decisions, approval gates, rollback, timeouts and a kill switch, then lint it with a bundled checker. Use when designing a new SOAR playbook, porting one between platforms (Sentinel Logic Apps, Splunk SOAR, XSOAR, Tines, Torq, Shuffle), or reviewing whether an existing playbook can fail safely.
license: MIT
metadata:
  category: security-automation
  version: "2.2.0"
  verification: tested
---

# SOAR Playbook Design

Design the playbook on paper as a graph first, lint the graph, and only then click it together in the vendor editor. Most production incidents caused by automation come from paths nobody drew: the `null` branch, the retry loop, the connector that hangs.

## 1. Decide whether to automate at all

Automate a step when **all** are true:

- The step is executed the same way by every analyst today (written runbook exists; see `runbook-authoring`).
- Volume justifies it (rule of thumb: > 20 executions per week, or the step blocks MTTR).
- Inputs are structured fields, not free text an analyst interprets.
- A wrong result is either harmless (enrichment, notification) or reversible and gated (containment).

Keep human: scoping, attribution, legal/HR decisions, anything irreversible (deleting mailboxes, wiping devices).

## 2. Model the playbook as a step graph

Write the playbook in this vendor-neutral JSON before building it. Every platform maps onto it.

```json
{
  "name": "phish-reported-email",
  "owner": "soc-automation",
  "kill_switch": "Disable Logic App 'pb-phish' or set flag automation/phish=off in the config list",
  "start": "parse",
  "steps": {
    "parse":   {"type": "query", "timeout_s": 60, "next": "enrich"},
    "enrich":  {"type": "enrich", "timeout_s": 120, "on_error": "manual", "next": "verdict"},
    "verdict": {"type": "decision", "branches": {"malicious": "approve", "benign": "close"}, "default": "manual"},
    "approve": {"type": "action", "action": "purge_message", "destructive": true, "approval": "soc-l2",
                "rollback": "restore_message", "idempotency_key": "{{message_id}}", "timeout_s": 300,
                "on_error": "manual", "next": "notify"},
    "restore_message": {"type": "action", "action": "restore_message", "timeout_s": 300, "approval": "soc-l2",
                "rollback": "purge_message", "destructive": false, "next": "notify"},
    "notify":  {"type": "notify", "next": "end"},
    "manual":  {"type": "notify", "next": "end"},
    "close":   {"type": "notify", "next": "end"},
    "end":     {"type": "end"}
  }
}
```

Step contract:

| Field | Meaning |
|---|---|
| `type` | `query`, `enrich`, `decision`, `action`, `notify`, `wait`, `end` |
| `next` / `branches` / `default` | Successors. A decision **must** have a `default` for values nobody planned for |
| `timeout_s` | Required on every external call |
| `on_error` | Where a connector failure goes (usually a "hand to analyst" step) |
| `destructive`, `approval`, `rollback`, `idempotency_key` | Required for anything that changes state in production |
| `auto_approved_by`, `exclusions` | Only for pre-approved automatic containment (see `automated-containment-guardrails`) |
| `max_iterations` | Required on any step that loops (polling, retries) |
| `params` | Connector parameters. Credentials are vault references, never literals |

## 3. Lint the graph

```bash
python3 scripts/playbook_lint.py playbooks/*.json --fail-on high
```

The linter reports dangling and unreachable steps, paths that never reach `end`, loops without `max_iterations`, decisions without a default, disruptive actions (explicit or by verb: isolate, disable, revoke, purge, ...) without approval/rollback/idempotency key, auto-approved actions without exclusions, external calls without timeouts, a missing owner or kill switch, and literal secrets in `params`. Exit code 1 when any finding reaches `--fail-on`; run it in CI next to the exported playbooks.

## 4. Design rules

1. **Trigger narrowly.** Bind to specific analytic rule IDs, not "any high-severity incident". Record the rule IDs in the playbook description.
2. **Enrich before you decide.** Decisions read fields, never raw text. Normalize verdicts to a small enum (`malicious`, `suspicious`, `benign`, `unknown`).
3. **Fail to a human.** Every `on_error` and `default` ends in an analyst task with the context gathered so far, never in a silent stop.
4. **Write back.** Each step comments on the incident: what ran, inputs, result, duration. The case must be reconstructable without the SOAR run history (which often expires after 30-90 days).
5. **Idempotency.** Re-running the playbook on the same incident must not double-act. Key actions on the entity (message ID, user object ID, device ID).
6. **Least privilege connectors.** One managed identity or service account per playbook, scoped to the actions it performs. A phishing playbook does not need `User.ReadWrite.All`.
7. **Kill switch.** A single documented control (disable the workflow, feature flag in a watchlist/config table) that stops all instances. Test it.

## 5. Platform mapping notes

| Concept | Sentinel (Logic Apps) | Splunk SOAR | Cortex XSOAR | Tines / Torq |
|---|---|---|---|---|
| Approval gate | Teams/Outlook approval action | `prompt` block | Data collection task / manual task | Prompt / Approval step |
| Timeout | Action retry policy + `timeout` setting | Block timeout | Task timeout | Action timeout |
| Kill switch | Disable the Logic App; automation rule order | Disable playbook / set inactive | Disable playbook trigger | Disable story / workflow |
| Secrets | Managed identity, Key Vault reference | Asset config | Credentials store | Credentials / secrets store |

## Output

- Step-graph JSON committed next to the exported vendor playbook.
- Linter output with zero `high`/`critical` findings or a documented exception.
- Runbook link, owner, kill switch and the analytic rule IDs that trigger it.

## Related skills

`playbook-testing`, `automation-risk-review`, `automated-containment-guardrails`, `enrichment-automation`, `runbook-authoring`, `alert-triage`

## References

- NIST SP 800-61r3 (Incident Response Recommendations): https://csrc.nist.gov/pubs/sp/800/61/r3/final
- Microsoft Sentinel playbooks: https://learn.microsoft.com/en-us/azure/sentinel/automation/automate-responses-with-playbooks
- Splunk SOAR playbooks: https://docs.splunk.com/Documentation/SOAR/current/Playbook/Overview
- CISA Federal Incident and Vulnerability Response Playbooks: https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks
