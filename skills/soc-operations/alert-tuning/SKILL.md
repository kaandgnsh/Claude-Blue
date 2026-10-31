---
name: alert-tuning
description: Reduce false positives in a detection rule without creating blind spots, using alert history, precise exclusions, and before/after measurement. Use when a rule is noisy, analysts are closing the same alert repeatedly, or someone requests an exclusion or suppression.
license: MIT
metadata:
  category: soc-operations
  version: "2.0.0"
  verification: documented
---

# Alert Tuning

Every exclusion is a hole an attacker can use. Tune with the narrowest possible condition, prove the effect, and give it an owner and an expiry.

## Inputs

- Rule ID, logic, and its intended ATT&CK technique.
- 30–90 days of alert history with dispositions (TP/BTP/FP).
- The exclusion request and the business justification.

## Workflow

1. **Quantify the noise.** Group historical alerts by the fields that vary:
   - Splunk: `index=notable search_name="<rule>" earliest=-30d | stats count by dest, user, process_name, parent_process_name | sort -count`
   - Sentinel: `SecurityAlert | where AlertName == "<rule>" and TimeGenerated > ago(30d) | extend e=parse_json(Entities) | summarize count() by CompromisedEntity`
2. **Find the root cause of the FP.** Is the logic wrong (matches too broadly), or is the behavior real but authorized? Fix logic first; exclude authorized behavior second.
3. **Choose the narrowest exclusion**, in this order of preference:
   1. Fix the logic (add a required field, tighten a regex, require a parent/child pair).
   2. Exclude on a combination (signed binary **and** exact path **and** parent), never a single weak field.
   3. Exclude by asset/user group maintained in a lookup with an owner.
   - Never exclude on: process name alone, `CommandLine contains` of a generic string, an entire subnet, or a user that can log in interactively.
4. **Check what the exclusion would hide.** Re-run the tuned logic over the same 30–90 days and diff: alerts removed must all be FP/BTP. Any removed TP → redesign.
5. **Document**: requester, justification, condition, expiry date (default 90 days), reviewer.
6. **Deploy via change control** (`detection-as-code`), then measure alert volume and TP rate for 2 weeks.

## Exclusion quality checklist

- [ ] Uses ≥2 independent attributes, at least one hard to spoof (signer, hash, parent, host group).
- [ ] Path conditions are full paths, case-normalized; no user-writable directories (`%TEMP%`, `Downloads`, `/tmp`).
- [ ] Has an expiry and owner; recorded in the rule's change log.
- [ ] Back-tested: no historical TP suppressed.
- [ ] A compensating detection exists if a known attack technique is now blind (e.g., signed-binary proxy execution).

## Output template

```
Rule: <name/id>  Period analysed: <dates>  Alerts: <n>  TP/BTP/FP: <a/b/c>
Root cause: <logic flaw | authorized behaviour>
Change: <diff of logic or exclusion>
Back-test: removed <n> alerts, all FP/BTP (query: <>)
Residual risk: <what is now not detected>
Owner: <>  Expiry: <date>  Change ticket: <>
```

## Safety

Do not disable a rule to stop noise during an active incident without the incident commander's approval. Suppressions on critical-tier assets need a second reviewer.

## Related skills

`alert-triage`, `detection-lifecycle`, `detection-as-code`, `soc-performance-metrics`

## References

- Palantir Alerting and Detection Strategy framework: https://github.com/palantir/alerting-detection-strategy-framework
- Sigma filter/correlation docs: https://sigmahq.io/docs/
