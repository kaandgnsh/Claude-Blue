---
name: ot-network-monitoring
description: Monitor OT/ICS networks for threats and unsafe changes — baseline of normal communications, ICS protocol write/program/stop commands (Modbus function codes, S7 PLC stop, CIP, DNP3 control), new devices, IT-to-OT crossings, remote access use — and triage OT alerts with operations staff. Use when deploying OT network detection, triaging ICS NDR alerts, or hunting in OT traffic.
license: MIT
metadata:
  category: ot-ics-security
  version: "2.0.0"
  verification: documented
---

# OT Network Monitoring

## Detection priorities

| Behaviour | Why | Example signals |
|---|---|---|
| Controller program/config changes | Logic manipulation (Stuxnet/TRITON-class) | S7comm download/upload blocks, CIP program download, vendor project download events outside maintenance windows |
| Operating mode changes | Stop/run/program mode changes halt processes | S7 PLC STOP (function `0x29`), Modbus write to mode registers, CIP `Stop` service |
| Write commands from unusual sources | Only HMIs/EWS should write | Modbus function codes 5/6/15/16 (writes) from a non-HMI IP; DNP3 operate/direct operate from new master |
| New devices / new conversations | Rogue laptops, attacker footholds | First-seen MAC/IP; new src–dst–port tuple at Level 1–2 |
| IT → OT crossings | Pivot from corporate | Direct connections from enterprise subnets to Level 2 bypassing DMZ jump hosts |
| Remote access sessions | Most common OT intrusion path | Vendor VPN/remote tool sessions outside approved windows |
| Reconnaissance | Pre-attack mapping | Broadcast discovery (`S7 SZL` reads, `ENIP ListIdentity`) from non-engineering hosts |
| Malware C2 / IT malware | Ransomware spreading into OT | SMB/RDP lateral movement, known C2 |

Zeek ICSNPP example — Modbus writes by source:
```sh
zeek-cut id.orig_h id.resp_h func < modbus.log | awk '$3 ~ /WRITE/' | sort | uniq -c | sort -rn
```
Field names follow the ICSNPP/Zeek package version.

## Triage with operations

OT alerts need process context: was there a maintenance window, a known engineer, a recipe change? Contact control room/engineering via agreed procedure before any response action; **never** isolate or block OT devices without the process owner (safety impact).

## Baseline

OT traffic is highly deterministic — after a learning period (2–4 weeks, covering operating modes), alert on deviations; document approved engineering activities to reduce noise.

## Related skills

`ot-asset-inventory`, `ot-incident-response`, `zeek-log-analysis`, `ot-segmentation-review`

## References

- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- CISA ICSNPP: https://github.com/cisagov/icsnpp
- NIST SP 800-82 Rev. 3: https://csrc.nist.gov/pubs/sp/800/82/r3/final
- SANS ICS Five Critical Controls (2022): https://www.sans.org/white-papers/five-ics-cybersecurity-critical-controls/
