---
name: correlation-rule-design
description: Design correlation and risk-based alerting (RBA) — multi-event sequences, threshold rules, entity risk scoring, cross-source joins (identity + endpoint + network), time windows and suppression — to raise fidelity without losing detection. Use when single-event rules are too noisy, when building Splunk RBA/Sentinel fusion-style logic, or when detecting multi-stage attacks.
license: MIT
metadata:
  category: siem-engineering
  version: "2.0.0"
  verification: documented
---

# Correlation and Risk-Based Alerting

## Patterns

| Pattern | Example | Implementation |
|---|---|---|
| Threshold | ≥ 20 failed logons for distinct users from one IP in 10 min | `stats dc(user) by src` / Sigma `value_count` correlation |
| Sequence | Phish click → new process from browser → outbound to new domain within 30 min | EQL `sequence`, KQL `join` on entity with time bounds, Sigma `temporal` |
| Cross-source | Risky sign-in **and** MFA method registered **and** inbox rule created for same user within 24h | Join identity + M365 audit |
| Risk-based | Each weak signal adds risk to entity; alert when entity risk ≥ threshold or ≥ N distinct ATT&CK tactics in 24h | Splunk ES RBA (`risk` index, risk incident rules); custom risk table in KQL |

## Risk-based alerting design

1. Convert noisy rules into **risk rules**: no alert, but write `risk_object`, `risk_score`, `threat_object`, ATT&CK technique.
2. Calibrate scores by fidelity and impact (e.g., 10 = weak anomaly, 40 = credential access signal, 80 = near-certain malicious).
3. **Risk incident rule**: alert when `sum(risk_score) ≥ 100` **or** `dc(tactic) ≥ 3` for an entity in 24h/7d.
4. Apply entity modifiers (privileged user ×1.5, Tier 0 host ×2).
5. Review top risk objects weekly to tune.

Splunk RBA incident rule sketch:
```spl
| tstats summariesonly=false sum(All_Risk.calculated_risk_score) as score dc(All_Risk.annotations.mitre_attack.mitre_tactic_id) as tactics
    values(source) as rules from datamodel=Risk.All_Risk by All_Risk.risk_object, All_Risk.risk_object_type
| where score >= 100 OR tactics >= 3
```
(Data model field names per Splunk ES version.)

## Sigma correlation example

```yaml
title: Many Failed Logons From Single Source
id: 3d2f8a7e-6b41-4c9a-8f0e-1a2b3c4d5e6f
name: failed_logon_spray
status: experimental
correlation:
  type: value_count
  rules:
    - failed_logon_base
  group-by:
    - IpAddress
  timespan: 10m
  condition:
    field: TargetUserName
    gte: 20
level: medium
```
(The base rule `failed_logon_base` selects EventID 4625.)

## Pitfalls

- Entity resolution: the same user as `alice`, `CORP\alice`, `alice@corp.com` must normalize to one risk object (`field-normalization`).
- Time windows vs. ingestion delay — late events miss the correlation window.
- Suppression that hides repeated true activity; suppress by entity + rule for a bounded period only.

## Related skills

`field-normalization`, `alert-tuning`, `sigma-authoring`, `password-spray-detection`

## References

- Splunk Risk-Based Alerting: https://docs.splunk.com/Documentation/ES/latest/RBA/RBAOverview
- Sigma correlation rules specification: https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md
- Elastic EQL sequences: https://www.elastic.co/guide/en/elasticsearch/reference/current/eql-syntax.html
