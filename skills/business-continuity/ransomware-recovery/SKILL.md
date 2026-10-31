---
name: ransomware-recovery
description: Plan and execute recovery from ransomware — clean-room/isolated recovery environment, restore order (identity first), validating backups are free of persistence, rebuilding vs. restoring, credential reset sequence, staged reconnection and business validation. Use after ransomware containment when systems must be restored, or when preparing a ransomware recovery plan.
license: MIT
metadata:
  category: business-continuity
  version: "2.0.0"
  verification: documented
---

# Ransomware Recovery

## Principles

- **Don't restore into a compromised environment**: rebuild trust (identity, admin tooling) first.
- **Restore points must predate the intrusion** (not just the encryption) or be scanned for the attacker's persistence and tooling.
- Recovery is a sequence; publish it so business owners know when to expect services.

## Recovery sequence (typical)

1. **Isolated recovery environment (IRE / clean room)**: separate network, clean admin workstations, new admin credentials, out-of-band communications.
2. **Identity**: AD forest recovery (restore one DC per domain from a known-good backup, seize FSMO, clean metadata, reset krbtgt twice, reset all privileged and service accounts, review GPOs/AdminSDHolder/ADCS) or rebuild; verify Entra Connect/federation integrity.
3. **Core infrastructure**: DNS, DHCP, PKI, hypervisors (often encrypted at ESXi level), backup infrastructure, security tooling (EDR, SIEM) — so restored systems are monitored from first boot.
4. **Tier 1 business services** per `critical-service-mapping` (dependencies first), then Tier 2/3.
5. **Endpoints**: reimage rather than clean.

## Validate restored systems

Scan with updated EDR/AV and YARA for the incident's IOCs (`incident-scoping` artefacts), check for persistence mechanisms found during the investigation, patch the initial access vector before reconnecting, verify integrity of application data (business owner sign-off).

## Reconnection

Stage by zone with monitoring; keep internet egress restricted initially; watch for the known TTPs and C2.

## Track

`Service | Tier | Dependencies | Restore source/point | Rebuild/restore | Validation (security/business) | ETA | Status`

Communicate progress to leadership and customers (via comms team).

## Related skills

`ransomware-response`, `backup-assurance`, `eradication-recovery`, `critical-service-mapping`

## References

- CISA #StopRansomware Guide: https://www.cisa.gov/stopransomware/ransomware-guide
- NIST SP 1800-11 Data Integrity: Recovering from Ransomware and Other Destructive Events: https://www.nccoe.nist.gov/data-integrity-recovering-ransomware-and-other-destructive-events
- Microsoft AD Forest Recovery Guide: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-guide
