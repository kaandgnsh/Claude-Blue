---
name: honeytoken-deployment
description: Deploy honeytokens and canaries for high-fidelity detection — decoy AD accounts with SPNs (Kerberoast canary), fake AWS access keys, canary documents and URLs, DNS tokens, decoy database rows and credentials in password stores — with alerting pipelines and safe placement. Use when you want low-noise detection of credential theft, reconnaissance and data access, or to detect attackers who evade other controls.
license: MIT
metadata:
  category: deception
  version: "2.0.0"
  verification: documented
---

# Honeytoken Deployment

Any interaction with a honeytoken is suspicious by design — false positives come mainly from your own scanners and backups, which you can document.

## Token types

| Token | Placement | Alert source |
|---|---|---|
| Decoy AD user with SPN (never used) | Looks like a service account (`svc_sqlbackup`), plausible description | DC 4769 for that SPN (Kerberoasting), 4768/4625 logons |
| Decoy privileged-looking account | Member of a decoy group named like an admin group (not actually privileged) | Any 4624/4625/4768 for it |
| Fake AWS access key | Stored in decoy `~/.aws/credentials`, CI variables, wiki pages, config files | CloudTrail events for that key ID (canary key services or own account with deny-all user) |
| Canary documents | File shares, SharePoint, executives' folders | Document open beacons (web bug/DNS) — Thinkst Canarytokens |
| DNS/URL tokens | Embedded in configs, scripts, internal docs | DNS resolution / HTTP request |
| Decoy database rows/credentials | Customer table row with unique email; fake connection strings | Email received at the unique address; login attempts |
| Browser-saved decoy credentials | On high-value endpoints | IdP failed logins for the decoy username |

## AD honey SPN detection (Sentinel)

```kusto
SecurityEvent
| where EventID in (4769, 4768, 4624, 4625) and (ServiceName =~ "svc_sqlbackup" or TargetUserName =~ "svc_sqlbackup")
| project TimeGenerated, EventID, Computer, IpAddress, TargetUserName, ServiceName, TicketEncryptionType
```
Create the account disabled-from-logon where possible (deny logon rights) but with an SPN so ticket requests still generate 4769 events; set a long random password.

## Rules

- Document every token (location, purpose, alert route) in a restricted register; exclude scanners/backup processes explicitly.
- Route alerts as high severity to the SOC with a dedicated runbook (`deception-alert-triage`).
- Don't place tokens where legitimate automation will touch them; test once after placement.
- Rotate/refresh tokens when they appear in reports or are discovered.

## Related skills

`deception-alert-triage`, `honeypot-deployment`, `kerberos-attack-detection`, `aws-credential-compromise`

## References

- Thinkst Canarytokens: https://canarytokens.org/
- MITRE Engage (adversary engagement framework): https://engage.mitre.org/
- MITRE D3FEND Decoy techniques: https://d3fend.mitre.org/
