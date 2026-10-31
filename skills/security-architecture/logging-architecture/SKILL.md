---
name: logging-architecture
description: Design security logging architecture — what each system must log, collection tiers (agents, syslog, cloud-native exports, APIs), pipeline/routing (Cribl, Vector, Kafka), SIEM vs. data lake storage (OCSF, Security Lake), retention tiers, integrity, access control and cost management. Use when designing or modernizing SIEM/data platforms, setting application logging standards, or estimating log costs.
license: MIT
metadata:
  category: security-architecture
  version: "2.0.0"
  verification: documented
---

# Security Logging Architecture

## Layers

1. **Sources**: identity (IdP, AD), endpoints (EDR, Sysmon, auditd), network (firewall, proxy, DNS, NDR/Zeek), cloud control/data plane, SaaS, applications, databases.
2. **Collection**: agents (Elastic Agent, Splunk UF, Azure Monitor Agent, Fluent Bit), syslog over TLS (RFC 5425), cloud exports (S3/Event Hub/Pub/Sub), API pollers.
3. **Pipeline**: parse, normalize (OCSF/ECS/ASIM), enrich (asset, identity, geo), filter/reduce noise, redact (`telemetry-minimization`), route by value: SIEM hot tier for detections, data lake (S3/ADLS/GCS + Athena/BigQuery, Amazon Security Lake in OCSF) for bulk/long retention.
4. **Storage & analytics**: SIEM for real-time detection; lake for hunting/forensics with search-on-demand.
5. **Consumers**: SOC, IR, hunting, compliance, ML.

## Application logging standard (minimum)

Authentication events (success/failure, MFA), authorization failures, admin actions, data export/bulk access, input validation failures at boundaries, configuration changes, security-relevant errors — with timestamp (UTC, ISO-8601), user/principal ID, tenant, source IP, request ID/trace ID, action, object, outcome. JSON structured; no secrets/PII payloads.

## Design checks

- Buffering/backpressure so outages don't lose logs (persistent queues).
- Time sync (NTP) everywhere; ingest time vs. event time recorded.
- Integrity: write-once storage for archives, separate admin domain for log platform.
- Access: role-based, audit of searches on sensitive indexes.
- Cost: price per GB per tier; reduce verbose sources (filter debug, sample flow logs for non-critical VPCs) rather than dropping security-critical events.
- Health monitoring (`log-pipeline-health`).

## Output

Architecture diagram + `Source | Events | Collector | Pipeline transforms | Destination tier | Retention | Owner | Cost/GB/day`

## Related skills

`log-source-onboarding`, `cloud-logging-baseline`, `field-normalization`, `telemetry-minimization`

## References

- NSA/CISA Best Practices for Event Logging and Threat Detection: https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- Amazon Security Lake (OCSF): https://docs.aws.amazon.com/security-lake/latest/userguide/what-is-security-lake.html
- OCSF: https://schema.ocsf.io/
