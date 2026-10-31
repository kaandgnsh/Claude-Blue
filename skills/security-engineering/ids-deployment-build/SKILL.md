---
name: ids-deployment-build
description: Deploy and operate a network IDS sensor with Suricata (optionally alongside Zeek) — capture design (SPAN/TAP, af-packet), HOME_NET and variables, rule sources with suricata-update, custom local rules, EVE JSON output to the SIEM, performance tuning, health monitoring — verified with suricata -T and PCAP replays. Use when building network detection for a segment or cloud VPC, standing up Security Onion-style sensors, or validating a Suricata configuration.
license: MIT
metadata:
  category: security-engineering
  version: "2.1.0"
  verification: documented
---

# IDS Deployment Build (Suricata)

Follows `secure-build-workflow`. Not executed in this repository: Suricata isn't available to the test suite. The validation steps are in section 5.

## 1. Capture design

| Environment | Capture |
|---|---|
| On-prem | Network TAP or switch SPAN of the chokepoint (internet edge, between zones, DC/Tier 0 segment) into a dedicated NIC with no IP |
| AWS | VPC Traffic Mirroring to the sensor ENI (VXLAN) |
| Azure | Virtual network TAP (where available) or NVA-based inspection |
| GCP | Packet Mirroring |

Size for peak throughput; for encrypted traffic, rely on metadata (TLS SNI/JA4, DNS, flow) rather than payload.

## 2. Install and base config

Debian/Ubuntu: `apt install suricata` (OISF PPA for current releases); RHEL: EPEL/COPR; or the `jasonish/suricata` container image.

`/etc/suricata/suricata.yaml` key settings:
```yaml
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
af-packet:
  - interface: ens5
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    threads: auto
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      community-id: true
      types:
        - alert:
            metadata: yes
        - dns
        - tls:
            extended: yes
        - http:
            extended: yes
        - flow
        - anomaly
        - stats:
            totals: yes
            threads: no
```
`community-id: true` lets you pivot between Suricata, Zeek and EDR flows.

## 3. Rules

```sh
sudo suricata-update update-sources
sudo suricata-update enable-source et/open          # plus licensed sources if available
sudo suricata-update --local /etc/suricata/rules/local.rules
```
- Manage `disable.conf`, `modify.conf` and `threshold.config` in Git.
- Disable noisy categories that don't fit your environment rather than whole sources.
- Write custom rules with `suricata-rule-authoring`.

## 4. Ship and monitor

- EVE JSON → SIEM via Filebeat/Elastic Agent, Vector, Fluent Bit or Splunk UF (`log-shipping-build`).
- Health: kernel drops (`capture.kernel_drops` in stats), `decoder.invalid`, rule load errors, EPS.
- Alert when the sensor goes silent or drops exceed 1% (`log-pipeline-health`).

## 5. Validate

```sh
sudo suricata -T -c /etc/suricata/suricata.yaml -v           # config + rules test
suricata -r sample.pcap -c /etc/suricata/suricata.yaml -l /tmp/suri -k none
jq -r 'select(.event_type=="alert") | .alert.signature' /tmp/suri/eve.json | sort | uniq -c
jq 'select(.event_type=="stats") | .stats.capture' /var/log/suricata/eve.json | tail -1
```
- Replay known-bad PCAPs (malware-traffic-analysis exercises, your own sandbox captures) and benign baseline PCAPs.
- Confirm expected alerts fire and no flood of false positives.
- Then check live: generate a test alert from a client (e.g., `curl http://testmynids.org/uid/index.html` triggers ET rule 2100498 "GPL ATTACK_RESPONSE id check returned root").

## Related skills

`secure-build-workflow`, `suricata-rule-authoring`, `suricata-alert-triage`, `zeek-log-analysis`, `log-shipping-build`

## References

- Suricata documentation: https://docs.suricata.io/
- suricata-update: https://suricata-update.readthedocs.io/
- Security Onion (integrated sensor platform): https://docs.securityonion.net/
- AWS VPC Traffic Mirroring: https://docs.aws.amazon.com/vpc/latest/mirroring/what-is-traffic-mirroring.html
