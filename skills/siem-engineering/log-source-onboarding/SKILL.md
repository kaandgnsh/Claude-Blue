---
name: log-source-onboarding
description: Onboard a new log source into a SIEM or data lake — define security use cases, required events and fields, collection method, parsing and normalization, volume/cost estimate, retention, health monitoring and acceptance tests. Use when adding logs (cloud, SaaS, firewall, EDR, application) or auditing whether an existing source is fit for detection.
license: MIT
metadata:
  category: siem-engineering
  version: "2.0.0"
  verification: documented
---

# Log Source Onboarding

## Onboarding record

| Item | Content |
|---|---|
| Source | Product, version, owner, asset scope (how many devices/tenants) |
| Use cases | Detections/hunts/investigations this enables (ATT&CK data components) |
| Events required | Specific event types/IDs/categories; audit settings required at source |
| Collection | Agent (UF, AMA, Elastic Agent, Cribl/Vector/Fluent Bit), syslog (TLS, RFC 5424), API pull (rate limits, polling interval), cloud-native export (CloudTrail→S3, Diagnostic settings→Event Hub/Log Analytics, GCP sink→Pub/Sub) |
| Parsing/normalization | Parser/add-on, target schema (CIM/ASIM/ECS/OCSF/UDM), field mapping table |
| Volume & cost | Events/day, GB/day, peak EPS, licence/ingest tier; filtering/reduction plan |
| Retention | Hot/searchable and archive periods vs. legal/IR requirements (≥ 90 days hot, ≥ 1 year total is common guidance; check regulations) |
| Time | Timezone, timestamp field, NTP status |
| Health | Expected interval, silence threshold alert, parsing-error alert |
| Access | Who can read (sensitive data?), PII handling |

## Workflow

1. Start from use cases, not "collect everything": list detections that need the source.
2. Enable required auditing at the source (e.g., Windows audit policy, CloudTrail data events for sensitive buckets, M365 audit, database audit).
3. Configure collection in test; capture sample raw events.
4. Map fields to the schema; verify with samples that key fields (user, src/dst IP, host, action, outcome, object) are populated.
5. **Acceptance tests**: generate known events (login success/failure, admin change) and confirm they arrive parsed within latency SLO.
6. Deploy health monitoring (`log-pipeline-health`) and document in the data catalog.

## Acceptance checklist

- [ ] Test events arrive within SLO (e.g., p95 < 5 min).
- [ ] Field fill rate ≥ 95% for required fields.
- [ ] Timestamps correct to the second in UTC.
- [ ] Silence alert configured and tested.
- [ ] Linked detections enabled and tested.

## Related skills

`field-normalization`, `log-pipeline-health`, `hunt-data-readiness`, `cloud-logging-baseline`

## References

- NSA/CISA "Best Practices for Event Logging and Threat Detection" (2024): https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection
- OMB M-21-31 logging maturity: https://www.whitehouse.gov/wp-content/uploads/2021/08/M-21-31-Improving-the-Federal-Governments-Investigative-and-Remediation-Capabilities-Related-to-Cybersecurity-Incidents.pdf
- OCSF: https://schema.ocsf.io/
