---
name: eradication-recovery
description: Plan eradication of attacker presence (persistence, accounts, credentials, vulnerable entry points) and safe recovery to production with validation and re-entry monitoring. Use after containment, when deciding rebuild vs. clean, or when defining "done" for an incident.
license: MIT
metadata:
  category: incident-response
  version: "2.0.0"
  verification: documented
---

# Eradication and Recovery

## Rebuild vs. clean

Rebuild from known-good media when: attacker had admin/root, kernel or bootkit suspected, unknown tooling, domain controller or identity system compromised, or confidence in cleanup is low. "Clean in place" is acceptable only for well-understood, low-privilege compromises with full artifact coverage.

## Eradication checklist

- [ ] Root cause closed (patch exploited vuln, close exposed service, fix misconfiguration, remove phishing path).
- [ ] All persistence from scoping removed and verified (services, tasks, run keys, WMI, cron/systemd, launchd, web shells, startup items, browser extensions).
- [ ] Attacker-created/modified accounts removed; group memberships reverted (compare with pre-incident baseline).
- [ ] Credentials rotated for every identity exposed: users, service accounts, local admin (LAPS), API keys, cloud keys, secrets in compromised repos/CI, certificates whose keys were on compromised hosts.
- [ ] Identity infrastructure: if domain admin compromised → krbtgt double reset, review AdminSDHolder, GPOs, trusts, ADCS templates; if Entra compromised → review federation settings, app registrations, CA policies, PIM.
- [ ] Tokens/sessions revoked after credential rotation.
- [ ] IOC/TTP detections deployed for re-entry.

## Recovery workflow

1. Prioritize restoration by business impact (`critical-service-mapping`).
2. Restore from backups verified to pre-date compromise and scanned for persistence (`backup-assurance`).
3. Harden before reconnecting (patch, baseline config, EDR installed and reporting).
4. Reconnect in stages; monitor each stage for the known TTPs.
5. Business owner validates function; security validates telemetry.
6. Maintain heightened monitoring for 30+ days.

## Output template

```
Eradication & recovery — <incident>
Root cause: <> — remediation: <> (verified <how>)
Persistence removed: <item> <verification>
Credentials rotated: <scope> <date>
Systems: <host> rebuild/clean <status> <validated by>
Re-entry detections: <ids>   Monitoring until: <date>
Residual risk: <>
```

## Related skills

`containment-plan`, `ransomware-recovery`, `backup-assurance`, `ad-privileged-access-review`, `after-action`

## References

- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- CISA Joint guide "Technical Approaches to Uncovering and Remediating Malicious Activity" (AA20-245A): https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-245a
