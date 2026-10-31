---
name: deception-alert-triage
description: Triage alerts from honeytokens, canary files and internal honeypots — verify it isn't a documented scanner or legitimate process, identify the source host and identity, determine how the attacker found the decoy, and escalate fast because deception alerts are high fidelity. Use when a canary, honeytoken, decoy account or honeypot fires.
license: MIT
metadata:
  category: deception
  version: "2.0.0"
  verification: documented
---

# Deception Alert Triage

## Workflow (target: verdict in < 30 minutes)

1. **Is it a known benign source?** Check the deception register's documented exclusions: vulnerability scanners, backup/indexing jobs, AV scans of file shares, the deception platform's own health checks. Match exact source IP/host and time window.
2. **Identify the source**: source IP → host (DHCP/EDR), logged-on user at that time (EDR, 4624 on the host), process making the connection (EDR network events).
3. **Determine the discovery path** — reveals attacker stage:
   | Token | Implies |
   |---|---|
   | Honey SPN ticket request | Kerberoasting (credential access) from that host/user |
   | Decoy account logon attempt | Credential dumping or directory enumeration, then use |
   | Fake cloud key used | Credentials file/repo/CI variable harvested — check where that key was placed |
   | Canary document opened | File share browsing/collection, or exfiltrated copy opened elsewhere (note external IP) |
   | Honeypot connection | Network scanning or lateral movement from source |
4. **Escalate** as a probable intrusion unless excluded (`escalation-decision`); begin `incident-scoping` from the source host and identity.
5. **Don't alert the attacker**: avoid visible changes to the decoy; keep tokens live while scoping (coordinate with IC).

## Common benign causes (document, then exclude precisely)

- Vulnerability scanners and asset discovery hitting honeypots.
- Backup, eDiscovery or search indexers opening canary documents on file shares.
- Security tools enumerating AD (PingCastle, BloodHound collections run by the security team) touching decoy accounts.
- Administrators testing the deception platform without notice.

Each benign cause gets an exclusion scoped to source host **and** account **and** time pattern, never a blanket exclusion of the token.

## Output

`Token | Fired at | Source (IP/host/user/process) | Benign check result | Discovery path | Verdict | Escalated to | Next pivots`

## Related skills

`honeytoken-deployment`, `honeypot-deployment`, `incident-scoping`, `kerberos-attack-detection`

## References

- Thinkst Canary documentation / Canarytokens: https://canarytokens.org/
- MITRE Engage: https://engage.mitre.org/
