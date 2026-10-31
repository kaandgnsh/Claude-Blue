---
name: ot-asset-inventory
description: Build an OT/ICS asset inventory safely — passive network discovery (Zeek with ICS parsers, Malcolm, commercial OT NDR), engineering documentation, PLC/HMI/historian/EWS records, firmware versions, protocols and Purdue level — without active scanning that can disrupt controllers. Use when starting an OT security program, preparing for IEC 62443/NERC CIP assessments, or scoping OT vulnerabilities.
license: MIT
metadata:
  category: ot-ics-security
  version: "2.0.0"
  verification: documented
---

# OT Asset Inventory

## Safety first

Active scanning (nmap, vulnerability scanners) can crash or disturb PLCs, safety systems and legacy devices. Default to **passive** methods; any active query must be vendor-supported, approved by the process owner, scheduled, and tested on a spare/lab device first.

## Sources

| Source | Provides |
|---|---|
| Passive monitoring (SPAN/TAP at Level 2/3 switches) with Zeek + ICS protocol parsers (Modbus, DNP3, S7comm, ENIP/CIP, BACnet, OPC UA), Malcolm, Security Onion, or Claroty/Nozomi/Dragos/Armis/Microsoft Defender for IoT | IPs, MACs, vendors (OUI), protocols, roles (master/slave), firmware strings from protocol traffic |
| Engineering workstation projects (TIA Portal, Studio 5000, etc.) | Controller models, firmware, I/O, logic versions |
| Network device configs, ARP/CAM tables | Connected devices per switch port |
| Asset registers, P&IDs, maintenance systems | Physical location, criticality, owner |
| Vendor remote-access lists | Third-party connectivity |

Zeek example on a capture from the OT span: `zeek -r ot.pcap` (with ICSNPP packages installed) → `modbus.log`, `dnp3.log`, `s7comm.log`, `enip.log`, `bacnet.log`; summarize talkers: `zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | sort | uniq -c | sort -rn`.

## Inventory fields

`Asset ID | Type (PLC/RTU/HMI/EWS/historian/safety/network) | Vendor/model | Firmware | IP/MAC | Purdue level / zone | Protocols | Process/function | Criticality (safety/production) | Owner | Location | Remote access | Last verified`

## Quality

Reconcile passive findings against documentation; unknown devices are findings (rogue laptops, cellular modems, undocumented remote access). Keep inventory updated by continuous passive monitoring.

## Related skills

`ot-network-monitoring`, `ot-vulnerability-management`, `ot-segmentation-review`, `asset-inventory-reconciliation`

## References

- CISA "Foundations for OT Cybersecurity: Asset Inventory Guidance" (2025): https://www.cisa.gov/resources-tools/resources/foundations-ot-cybersecurity-asset-inventory-guidance-owners-and-operators
- CISA ICSNPP Zeek parsers: https://github.com/cisagov/icsnpp
- Malcolm: https://github.com/cisagov/Malcolm
- NIST SP 800-82 Rev. 3 Guide to OT Security: https://csrc.nist.gov/pubs/sp/800/82/r3/final
