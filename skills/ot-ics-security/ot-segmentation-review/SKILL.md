---
name: ot-segmentation-review
description: Review OT network segmentation and remote access — Purdue/IEC 62443 zones and conduits, IT/OT DMZ, firewall rules between levels, dual-homed hosts, cellular modems, vendor remote access paths and jump hosts — using configs and passive flow evidence. Use when assessing OT architecture, before connecting OT to cloud/IT, or after IT-side ransomware raised OT exposure concerns.
license: MIT
metadata:
  category: ot-ics-security
  version: "2.0.0"
  verification: documented
---

# OT Segmentation Review

## Reference model

| Level | Contents | Allowed crossing |
|---|---|---|
| 4–5 Enterprise | Corporate IT, ERP, email | Only to Level 3.5 DMZ |
| 3.5 IT/OT DMZ | Historian replica, patch/AV staging, jump hosts, remote access gateways | Brokers all IT↔OT traffic; no direct IT→Level 3 or below |
| 3 Site operations | Historian, MES, domain (OT), engineering servers | From DMZ only, specific services |
| 2 Area supervisory | HMIs, engineering workstations | From Level 3 |
| 1 Basic control | PLCs, RTUs, controllers | From Level 2 only |
| 0 Process | Sensors, actuators | — |
| SIS | Safety instrumented systems | Isolated; read-only data out where needed |

IEC 62443-3-2 defines zones (grouped by security requirements) and conduits (controlled communication paths) with target security levels.

## Review checks

- [ ] No direct routes IT ↔ Level 2/1; all traffic terminates in the DMZ (no "pass-through" rules).
- [ ] Firewall rules between levels are specific (src/dst/port), documented and reviewed; no `any` rules; logging enabled.
- [ ] No dual-homed hosts bridging IT and OT (check engineering laptops, historians with two NICs).
- [ ] No undocumented cellular/4G/5G modems or Wi-Fi bridges on OT devices (passive discovery, physical walkdown).
- [ ] Remote access: MFA, through DMZ jump hosts, session recording, vendor access enabled per session (time-boxed), no always-on vendor VPNs or direct remote tools on HMIs.
- [ ] Separate OT identity domain; no IT domain admins with OT admin rights.
- [ ] SIS network isolated from control network or strictly limited.
- [ ] Flow evidence (passive monitoring, firewall logs) confirms the design.

## Output

`Zone/conduit | Rule/flow | Purpose | Compliant | Risk | Recommendation | Owner`

## Safety

Changes to OT firewalls require operations approval and testing — a blocked control flow can stop production or affect safety.

## Related skills

`ot-network-monitoring`, `network-segmentation-review`, `third-party-access-review`, `ot-asset-inventory`

## References

- ISA/IEC 62443 series overview: https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards
- NIST SP 800-82 Rev. 3: https://csrc.nist.gov/pubs/sp/800/82/r3/final
- CISA "Principles of OT Cyber Security" (2024): https://www.cisa.gov/resources-tools/resources/principles-operational-technology-cybersecurity
