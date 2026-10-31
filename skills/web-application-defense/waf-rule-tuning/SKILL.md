---
name: waf-rule-tuning
description: Tune web application firewalls (OWASP Core Rule Set on ModSecurity/Coraza, AWS WAF, Azure WAF, Cloudflare, Akamai) — paranoia levels and anomaly thresholds, false-positive exclusions scoped by rule, path and parameter, detect-to-block rollout, virtual patching for new CVEs, and log review. Use when deploying a WAF, when it blocks legitimate traffic, or when a virtual patch is needed before an application fix.
license: MIT
metadata:
  category: web-application-defense
  version: "2.0.0"
  verification: documented
---

# WAF Rule Tuning

## OWASP CRS basics

Anomaly scoring: each matching rule adds to a score; the request is blocked when the inbound score ≥ threshold (default 5). **Paranoia level** 1 (default) → 4 increases coverage and false positives.

Rollout: detection-only mode (`SecRuleEngine DetectionOnly`) → review logs → exclusions → raise to blocking at PL1 → consider PL2 for sensitive apps.

## Scoped exclusions (CRS, ModSecurity syntax)

```apache
# Exclude one parameter from one rule on one path (e.g. a rich-text field triggering XSS rule 941100)
SecRule REQUEST_URI "@beginsWith /cms/editor/save" \
    "id:1001,phase:1,pass,nolog,ctl:ruleRemoveTargetById=941100;ARGS:content"
```
Never disable whole rule groups globally to fix one form. CRS also ships application exclusion packages (WordPress, Drupal, Nextcloud…) as plugins.

Cloud WAFs: AWS WAF managed rule groups with **rule action overrides** (count) and scope-down statements; Azure WAF exclusions per rule/request attribute; Cloudflare managed rules with exceptions by path/field.

## False-positive triage

From WAF logs: rule ID, matched variable/value, URI, client. Ask: is the input legitimate (business content) or is the app vulnerable? Fix in the app where possible; exclude narrowly otherwise; record owner and date.

## Virtual patching

For a new CVE: understand the exploit vector (`cve-technical-analysis`), write a precise rule on the vulnerable path/parameter (match exploit characteristics, not just generic attacks), deploy in count/log first briefly if safe, then block; remove after the application is patched.

```apache
SecRule REQUEST_FILENAME "@endsWith /vulnerable/endpoint" \
    "id:1002,phase:2,deny,status:403,log,msg:'Virtual patch CVE-XXXX-YYYY',chain"
    SecRule ARGS:template "@rx \$\{" "t:none,t:urlDecodeUni"
```

## Monitoring

Block counts by rule/path, top sources, false-positive reports from users, bypass attempts (encoding variations), and correlation with application errors.

## Related skills

`web-server-log-analysis`, `credential-stuffing-defense`, `cve-technical-analysis`, `api-abuse-detection`

## References

- OWASP Core Rule Set documentation: https://coreruleset.org/docs/
- CRS rule exclusion guidance: https://coreruleset.org/docs/concepts/false_positives_tuning/
- AWS WAF managed rule groups: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html
- Azure WAF exclusions: https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-configuration
