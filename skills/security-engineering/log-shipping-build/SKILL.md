---
name: log-shipping-build
description: Build a reliable, secure log shipping pipeline from hosts and services to a SIEM with Vector or Fluent Bit — source selection (journald, files, syslog, Windows events via agent), parsing, secret/PII redaction, TLS with certificate verification, disk buffering and backpressure, health metrics — verified with config validation and test events. Use when onboarding hosts to a SIEM, replacing unmaintained forwarders, or fixing lost or unparsed security logs.
license: MIT
metadata:
  category: security-engineering
  version: "2.1.0"
  verification: documented
---

# Log Shipping Build (Vector / Fluent Bit)

Follows `secure-build-workflow`. Not executed in this repository: Vector and Fluent Bit aren't available to the test suite. The validation steps are in section 3.

## 1. Requirements

Which security events are required (`log-source-onboarding`), the destination (Splunk HEC, Elastic, Sentinel/Log Analytics, OpenSearch, S3), delivery guarantees, how long the host must buffer during outages, and redaction needs (`telemetry-minimization`).

## 2. Vector example (`/etc/vector/vector.yaml`)

```yaml
sources:
  journald:
    type: journald
    current_boot_only: false
  auth_file:
    type: file
    include: ["/var/log/auth.log", "/var/log/secure"]
  audit_file:
    type: file
    include: ["/var/log/audit/audit.log"]

transforms:
  enrich_redact:
    type: remap
    inputs: ["journald", "auth_file", "audit_file"]
    source: |
      .host = get_hostname!()
      .shipper = "vector"
      if exists(.message) {
        .message = redact(string!(.message), filters: [r'(?i)(password|passwd|token|secret)=\S+', "us_social_security_number"])
      }

sinks:
  siem:
    type: splunk_hec_logs
    inputs: ["enrich_redact"]
    endpoint: "https://hec.siem.example.com:8088"
    default_token: "${SPLUNK_HEC_TOKEN}"
    index: "linux"
    encoding:
      codec: json
    tls:
      verify_certificate: true
      verify_hostname: true
      ca_file: "/etc/vector/siem-ca.pem"
    buffer:
      type: disk
      max_size: 1073741824        # 1 GiB on-disk buffer
      when_full: block
    acknowledgements:
      enabled: true
```
- Put the token in `/etc/default/vector` (mode 0600) or the secret store, not in the YAML.
- Run Vector as a dedicated user that is in the groups able to read the logs (`systemd-journal`, `adm`), not as root, where possible.

## Fluent Bit equivalent (YAML config, v3+)

```yaml
pipeline:
  inputs:
    - name: systemd
      tag: host.journal
      read_from_tail: on
  outputs:
    - name: http
      match: "*"
      host: collector.siem.example.com
      port: 443
      uri: /ingest
      format: json
      tls: on
      tls.verify: on
      header: Authorization Bearer ${INGEST_TOKEN}
      storage.total_limit_size: 1G
service:
  storage.path: /var/lib/fluent-bit/buffer
```

## 3. Validate

```sh
vector validate /etc/vector/vector.yaml            # config + sink health checks
vector tap enrich_redact                           # watch events flowing (Vector API must be enabled)
logger -p auth.warning "cb-pipeline-test $(date -u +%FT%TZ) password=shouldberedacted"
```
Search the SIEM for `cb-pipeline-test`. It must arrive within the latency target, and with `password=[REDACTED]`. Then simulate an outage (block the SIEM endpoint with a temporary firewall rule) and confirm the buffer grows and drains after recovery with no gaps.

## 4. Operate

Expose internal metrics (Vector `internal_metrics` source with a Prometheus exporter; Fluent Bit HTTP server metrics). Alert on buffer usage, sink errors, discarded events and source silence (`log-pipeline-health`). Pin versions and roll out via configuration management.

## Related skills

`secure-build-workflow`, `log-source-onboarding`, `log-pipeline-health`, `telemetry-minimization`, `logging-architecture`

## References

- Vector documentation: https://vector.dev/docs/
- Vector Remap Language `redact`: https://vector.dev/docs/reference/vrl/functions/#redact
- Fluent Bit documentation: https://docs.fluentbit.io/manual
- Splunk HTTP Event Collector: https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
