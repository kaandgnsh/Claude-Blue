---
name: playbook-testing
description: Test a SOAR playbook before and after release with replayed incidents, mocked connectors, negative and failure-path cases, a staging tenant and a canary rollout. Use when a new or changed playbook is about to go live, after a connector or API version change, or when an automation misfired and you need a regression test.
license: MIT
metadata:
  category: security-automation
  version: "2.2.0"
  verification: documented
---

# Playbook Testing

A playbook is code that runs with production credentials against production identities and hosts. Test it like code: deterministic inputs, expected outputs, failure injection, and a gradual rollout.

## Test levels

| Level | What runs | Where | Gate |
|---|---|---|---|
| Static | Step graph through the `playbook_lint.py` checker bundled with `soar-playbook-design`; export diff review | CI | Zero high/critical findings |
| Unit | Single steps with mocked connectors (canned JSON responses) | SOAR dev instance / local harness | Each step's output matches expected fields |
| Replay | Full playbook on sanitized copies of real past incidents | Staging tenant / test workspace | Decisions match the analyst's original disposition |
| Failure | Connector timeouts, 401/403/429/500, empty results, malformed fields | Staging | Every failure ends in an analyst task, no partial action |
| Canary | Live, but actions in "recommend only" mode or limited to a pilot group | Production | Precision and error rate over 2 weeks |

## Build the test corpus

Collect **at least 20 past incidents** per playbook from case history and label the expected path:

```text
case-id | rule        | expected verdict | expected actions                   | notes
1042    | Phish-Report| malicious        | purge(2 messages), block sender    | multi-recipient
1077    | Phish-Report| benign           | close BTP                          | marketing mail
1101    | Phish-Report| unknown          | manual                             | sandbox timeout
```

Include deliberately awkward inputs:

- Entity fields that are empty, `null`, arrays instead of strings, Unicode/IDN domains, very long values.
- Duplicate triggers for the same incident within seconds (idempotency).
- A VIP or break-glass account and a crown-jewel host (must hit exclusions, see `automated-containment-guardrails`).
- An incident that was later reclassified (the playbook must not act on stale verdicts).

## Mock connectors

Return recorded responses instead of calling live APIs. Record once from the real API in a test tenant, scrub tokens and personal data, store as fixtures:

```text
fixtures/
  virustotal/file_known_bad.json
  virustotal/429_rate_limited.json
  graph/user_disabled_already.json
  edr/isolate_timeout.json
```

Most platforms support this natively (XSOAR test playbooks with mock integrations, Splunk SOAR custom function stubs, Tines "test mode" with fixture events). For Logic Apps, point HTTP actions at a mock endpoint via a parameter switched per environment.

## Failure-path checklist

For each external step, inject and record the outcome:

- [ ] Timeout: run reaches the `on_error` step, analyst task created, nothing partially executed.
- [ ] 401/403: alert to automation owner (credential expired or permission removed), not a silent skip.
- [ ] 429: bounded retry with backoff (`max_iterations`), then hand off.
- [ ] Empty/unknown result: decision takes the `default` branch.
- [ ] Partial success (2 of 5 mailboxes purged): result recorded per entity, rollback possible per entity.
- [ ] Kill switch: flipped during a run; in-flight and queued runs stop.

## Canary rollout

1. **Recommend-only** for 1-2 weeks: the playbook posts "would have done X" to the case; analysts mark agree/disagree.
2. Promote when precision on disruptive steps is ≥ 99% over at least 50 cases and no failure-path gaps remain.
3. Enable actions for a pilot scope (one business unit, non-production device group), then widen.
4. Keep a regression set: every misfire becomes a new replay case.

## Regression triggers

Re-run the replay and failure suites when: a connector or API version changes, the analytic rule feeding the playbook changes, field mappings or entity extraction change, or the platform upgrades.

## Output

```markdown
# Playbook test report: <playbook> v<version>  Date: <date>
Static lint: pass (0 high)   Replay: 23/24 match (1 expected-manual)   Failure paths: 6/6
Canary: recommend-only 14 days, 61 cases, 0 disagreements on disruptive steps
Open issues: <list>   Decision: promote to pilot scope <scope>
```

## Related skills

`soar-playbook-design`, `automation-risk-review`, `automated-containment-guardrails`, `automation-metrics`, `detection-validation`

## References

- Microsoft Sentinel, test and troubleshoot playbooks: https://learn.microsoft.com/en-us/azure/sentinel/automation/automate-responses-with-playbooks
- Cortex XSOAR test playbooks: https://xsoar.pan.dev/docs/integrations/test-playbooks
- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
