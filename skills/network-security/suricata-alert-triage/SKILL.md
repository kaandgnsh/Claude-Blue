---
name: suricata-alert-triage
description: Triage Suricata/Snort/Zeek-notice IDS alerts using eve.json fields, the signature's logic, flow and app-layer metadata, payload/PCAP evidence and host corroboration to decide true/false positive and whether an attack succeeded. Use when working network IDS alerts in a SOC or from Security Onion, SELKS or a commercial NDR.
license: MIT
metadata:
  category: network-security
  version: "2.0.0"
  verification: documented
---

# Suricata Alert Triage

## Read the evidence

`eve.json` alert record fields: `timestamp`, `src_ip/src_port`, `dest_ip/dest_port`, `proto`, `app_proto`, `alert.signature_id`, `alert.signature`, `alert.category`, `alert.severity`, `alert.metadata`, `flow_id`, `payload_printable` (if enabled), plus linked `http`, `tls`, `dns`, `fileinfo` records with the same `flow_id`.

```sh
jq -c 'select(.event_type=="alert") | {t:.timestamp, sid:.alert.signature_id, sig:.alert.signature, src:.src_ip, dst:.dest_ip, flow:.flow_id}' eve.json | head
jq -c 'select(.flow_id==1234567890)' eve.json          # everything about that flow
```

## Triage questions

1. **What does the rule match?** Pull the rule text (`grep 'sid:2027865;' /var/lib/suricata/rules/suricata.rules`) — understand which content triggered.
2. **Direction & asset**: inbound exploit attempt vs. outbound C2/check-in. Outbound from an internal host is generally higher priority.
3. **Did it succeed?** For exploits: was the target vulnerable (version, patch level), did it respond with success (HTTP 200 with expected content vs. 404/403), any callback from target afterwards? Most inbound exploit alerts are internet noise against non-vulnerable services.
4. **Corroborate** on the host via EDR (process making the connection), and in DNS/proxy logs.
5. **Prevalence**: same SID across many hosts (policy/FP) vs. one host (targeted).
6. **Rule quality**: ET "INFO"/"POLICY" categories describe activity, not maliciousness.

## Verdict matrix

| Situation | Verdict / action |
|---|---|
| Inbound scan/exploit, target not vulnerable/no response | Benign (attempt), tune or aggregate; report to vuln mgmt if exposure is unintended |
| Inbound exploit + success indicators/callback | Incident — `incident-scoping` |
| Outbound C2/malware signature + host process corroborated | TP — `edr-alert-investigation`, `host-isolation` |
| Outbound signature, legit software (updater/telemetry) | FP — suppress narrowly (`threshold`/`suppress` by sid + ip) |

## Related skills

`suricata-rule-authoring`, `pcap-analysis`, `alert-triage`, `zeek-log-analysis`

## References

- Suricata EVE JSON format: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
- Security Onion documentation: https://docs.securityonion.net/
