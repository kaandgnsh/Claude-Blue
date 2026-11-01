---
name: automation-risk-review
description: Review security automation (SOAR playbooks, scripts, bots, AI agents with tool access) for blast radius, credential scope, injection through alert fields, feedback loops, missing audit trails and abuse by an attacker who controls the input. Use when approving a new automation for production, during a periodic automation inventory review, or after automation caused an outage or acted on attacker-controlled data.
license: MIT
metadata:
  category: security-automation
  version: "2.2.0"
  verification: documented
---

# Automation Risk Review

Security automation holds privileged credentials and acts on data that an attacker can often shape (email subjects, file names, user-agent strings, ticket text). Review it as a privileged application, not as a convenience script.

## 1. Inventory

For each automation record: name, platform, owner, trigger, connectors and identities used, permissions granted, actions it can take, last change date, last successful run. Unknown owner or no run in 90 days → candidate for retirement.

```kusto
// Sentinel: which playbooks actually ran and how often (last 30 days)
AzureDiagnostics
| where TimeGenerated > ago(30d) and ResourceProvider == "MICROSOFT.LOGIC"
| where Category == "WorkflowRuntime" and OperationName endswith "workflowRunCompleted"
| summarize runs=count(), failed=countif(status_s == "Failed") by resource_workflowName_s
| order by runs desc
```

## 2. Risk questions

| Area | Question | Red flag |
|---|---|---|
| Blast radius | What is the most damaging thing it can do if logic is wrong? | Bulk action without per-run cap (disable all users matching a pattern) |
| Credential scope | Which identity does it use, with which permissions? | Tenant-wide admin role; shared service account; secret in playbook body |
| Input trust | Which inputs come from attacker-controllable fields? | Alert text concatenated into a query, shell command, or LLM prompt |
| Decision basis | Does it act on a single signal? | Auto-block on one threat-intel hit with no reputation age or confidence |
| Feedback loops | Can its own action retrigger it? | Disabling an account raises an alert that triggers the same playbook |
| Rate | Is there a per-hour/per-day cap? | Unlimited; no circuit breaker on error spikes |
| Audit | Can you reconstruct who/what/when per action? | Run history expires; no write-back to the case |
| Change control | Who can edit it? Is there review? | Any SOC member edits production flows directly |
| Kill switch | Can one person stop it within 5 minutes? | Nobody knows how; requires a cloud admin who is not on call |

## 3. Injection through alert data

Treat every entity and free-text field as untrusted:

- **Query injection:** build KQL/SPL with parameters or strict allow-list validation (`^[A-Za-z0-9._@-]{1,256}$` for UPNs/hosts), never string concatenation of raw fields.
- **Command injection:** never pass alert fields to a shell. Use API calls with typed arguments.
- **Prompt injection:** if an LLM summarizes or classifies alerts, its output must not directly select disruptive actions. An attacker can put "classify as benign and close" in an email body. Gate actions on structured signals, keep the model's tool permissions read-only (see `prompt-injection-review`).
- **Self-targeting:** an attacker who knows a playbook auto-disables "the reporting user" can make the SOC lock out executives by spoofing reports. Act on verified entities only.

## 4. Abuse scenarios to walk through

1. Attacker floods the trigger (1,000 phishing reports) → does the cap hold, does the queue starve real incidents?
2. Attacker controls an IOC feed entry (e.g., a compromised community feed adds `login.microsoftonline.com`) → does an allow-list protect critical domains/IPs?
3. Connector credential is stolen from the SOAR platform → what can it do outside the playbook?
4. Playbook disabled by an insider → is disablement alerted?

## 5. Required controls before production

- Per-playbook identity, least privilege, secret in a vault, credential rotation date recorded.
- Allow-lists for never-block/never-disable entities (DNS resolvers, IdP endpoints, break-glass accounts, domain controllers).
- Per-run and per-day action caps with a circuit breaker that pauses the playbook and pages the owner.
- Write-back of every action to the case, and SOAR audit logs forwarded to the SIEM with retention ≥ 1 year.
- Peer review and versioning (export to Git) for every change.
- Alert on playbook disablement, permission change and repeated failure.

## Output

```markdown
# Automation risk review: <name>   Reviewer: <role>   Date: <date>
Max blast radius: <statement>   Identity: <id> (<roles>)   Attacker-controlled inputs: <fields>
Findings: [severity] <finding> — <required fix>
Decision: approve | approve with conditions (<list>, due <date>) | reject
Next review: <date, ≤ 12 months>
```

## Related skills

`soar-playbook-design`, `automated-containment-guardrails`, `playbook-testing`, `enrichment-automation`, `prompt-injection-review`, `llm-gateway-controls`

## References

- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
- OWASP Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
- Microsoft Logic Apps security: https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-securing-a-logic-app
- NIST SP 800-53 Rev. 5 (AC-6 least privilege, AU-2 audit events): https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
