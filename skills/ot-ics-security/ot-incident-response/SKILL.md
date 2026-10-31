---
name: ot-incident-response
description: Respond to incidents affecting OT/ICS environments — safety-first decision making with operations, IT-to-OT spread assessment (e.g., ransomware), evidence collection from HMIs/EWS/historians without disrupting process, controller integrity checks, manual operations and recovery. Use when an incident touches industrial control systems, building systems, or OT networks, or when IT ransomware threatens OT.
license: MIT
metadata:
  category: ot-ics-security
  version: "2.0.0"
  verification: documented
---

# OT Incident Response

## Priorities (in order)

1. **Human safety and environment** — the operations team and safety systems decide on process state.
2. **Process availability/integrity** — keep running safely or perform controlled shutdown.
3. **Containment and evidence**.

Security responders advise; plant/operations leadership owns process decisions.

## Initial assessment

- Is the incident in IT only, with risk of spread (common), or inside OT?
- Can operators trust HMI views? (Manipulated displays are a known attack aim — cross-check with field instruments/local panels.)
- Are safety systems (SIS) unaffected and independent?
- Is precautionary IT/OT disconnection needed? Pre-plan the "island" procedure: disconnect DMZ conduits while OT keeps running (verify dependencies: licensing servers, historians, time sync, AD).

## Evidence collection (low-impact)

- Network: passive capture from existing taps/span (`pcap-analysis`, `ot-network-monitoring` data).
- Windows-based HMIs/EWS/historians: triage collections (Velociraptor offline collector / KAPE) during approved windows; memory capture only if safe.
- Controllers: compare running logic/configuration with known-good offline copies using vendor tools (project compare / checksum features) — performed by control engineers.
- Logs: firewall, remote access gateway, historian audit, engineering software logs.

## Recovery

Restore HMIs/EWS from known-good images; verify controller logic and setpoints against approved baselines; validate with operations before returning to automatic control; rotate credentials (including vendor and shared OT accounts).

## Preparation (do before incidents)

OT-specific IR playbooks, contact trees with control-room numbers, offline copies of logic and configurations, manual operating procedures, spare HMI/EWS images, joint IT/OT/vendor exercises.

## Related skills

`ot-network-monitoring`, `ransomware-response`, `ot-segmentation-review`, `incident-command`

## References

- CISA ICS incident response resources: https://www.cisa.gov/topics/industrial-control-systems
- NIST SP 800-82 Rev. 3 (incident response for OT): https://csrc.nist.gov/pubs/sp/800/82/r3/final
- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
