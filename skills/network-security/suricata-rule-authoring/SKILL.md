---
name: suricata-rule-authoring
description: Write and test Suricata (and Snort-compatible) IDS/IPS signatures — header, flow, sticky buffers (http.uri, tls.sni, dns.query, file.data), content/pcre options, thresholds, metadata — and validate against PCAPs before deployment. Use when creating network detections for C2, exploits or malware traffic, or converting threat intel into IDS rules.
license: MIT
metadata:
  category: network-security
  version: "2.0.0"
  verification: documented
---

# Suricata Rule Authoring

## Anatomy (Suricata 7 syntax)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"CORP MALWARE Example loader check-in"; \
  flow:established,to_server; \
  http.method; content:"POST"; \
  http.uri; content:"/gate.php"; endswith; \
  http.user_agent; content:"MSIE 6.0"; \
  http.header_names; content:!"Referer"; \
  classtype:trojan-activity; sid:9000001; rev:1; \
  metadata:created_at 2026_10_31, mitre_technique_id T1071.001, confidence Medium;)
```
- Use **sticky buffers** (`http.uri;`, `http.host;`, `tls.sni;`, `dns.query;`, `file.data;`, `ja3.hash;`, `ja4.hash;` — availability depends on version/build) followed by content matches.
- Every rule needs a `flow:` direction for TCP protocols, a unique `sid` in your private range (e.g., ≥ 9,000,000 is commonly used locally — check your feed's ranges), and `rev`.
- Anchor matches (`startswith`, `endswith`, `depth`, `offset`, `distance`, `within`) and put the most unique content first (Suricata's fast pattern; force with `fast_pattern;`).
- Avoid PCRE without a preceding content (performance).
- DNS: `alert dns any any -> any any (msg:"..."; dns.query; content:"evil-example.test"; nocase; endswith; sid:9000002; rev:1;)`
- TLS SNI: `alert tls $HOME_NET any -> any any (msg:"..."; tls.sni; content:"bad.example"; nocase; endswith; sid:9000003; rev:1;)`
- Thresholding: `threshold:type limit, track by_src, count 1, seconds 3600;` to limit noise.

## Test before deploy

```sh
suricata -T -c /etc/suricata/suricata.yaml -S local.rules          # syntax check (test mode)
suricata -r sample.pcap -S local.rules -l ./out -k none             # run against PCAP; -k none ignores checksums
jq 'select(.event_type=="alert") | .alert.signature' out/eve.json
```
Test with a positive PCAP (sandbox traffic, `pcap-analysis` exports) and a benign PCAP of normal traffic to estimate FPs. Rule profiling: enable `profiling.rules` in suricata.yaml to find slow rules.

## Deployment

Manage with `suricata-update` (add local rules file via `--local`), keep rules in Git (`detection-as-code`), start in alert mode before IPS drop mode.

## Related skills

`suricata-alert-triage`, `pcap-analysis`, `intel-to-detection`, `detection-as-code`

## References

- Suricata rules documentation: https://docs.suricata.io/en/latest/rules/index.html
- suricata-update: https://suricata-update.readthedocs.io/
- Emerging Threats rules (examples/style): https://rules.emergingthreats.net/
