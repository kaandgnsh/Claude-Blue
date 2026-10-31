---
name: dcsync-detection
description: Detect DCSync and DCShadow — directory replication requested by non-DC principals — using event 4662 replication GUIDs, network DRSUAPI traffic and replication-rights audits. Use when credential dumping of the domain is suspected, when Mimikatz lsadump::dcsync is alerted, or when reviewing who holds replication rights.
license: MIT
metadata:
  category: active-directory-security
  version: "2.0.0"
  verification: documented
---

# DCSync / DCShadow Detection

## Background

DCSync (T1003.006) uses the Directory Replication Service (DRSUAPI `GetNCChanges`) to pull password hashes, requiring the extended rights **DS-Replication-Get-Changes** `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` and **DS-Replication-Get-Changes-All** `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (plus optionally `89e95b76-444d-4c62-991a-0facbeda640c` In-Filtered-Set). Legitimate callers: domain controllers and (scoped) Entra Connect / MDI sensors.

## Event-based detection

Enable *Audit Directory Service Access* on DCs and a SACL on the domain root for the replication rights. Then:

Sentinel:
```kusto
SecurityEvent
| where EventID == 4662
| where Properties has_any ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c")
| where SubjectUserName !endswith "$"
| project TimeGenerated, Computer, SubjectUserName, SubjectDomainName, Properties
```
Filter out the documented Entra Connect `MSOL_`/sync account only by exact name. Machine accounts (`$`) that are **not** DCs are also suspicious — compare against the DC list rather than filtering all `$`.

## Network detection

DRSUAPI `DRSGetNCChanges` RPC from a source IP that isn't a DC (Zeek `dce_rpc.log` `endpoint=drsuapi operation=DRSGetNCChanges`; Microsoft Defender for Identity alert "Suspected DCSync attack").

## DCShadow (T1207)

Rogue DC registration: creation of `nTDSDSA` objects / server objects under `CN=Sites` by non-DC hosts, SPNs `GC/` or `E3514235-4B06-11D1-AB04-00C04FC2DCD2/` added to a non-DC computer (5136 events), followed by replication from that host.

## Audit replication rights

```powershell
$dn = (Get-ADDomain).DistinguishedName
(Get-Acl "AD:$dn").Access | Where-Object { $_.ObjectType -in @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') } |
  Select-Object IdentityReference, ActiveDirectoryRights, ObjectType
```
Anything other than Domain Controllers, Enterprise Domain Controllers, Administrators/Enterprise Admins (inherited) and the scoped sync account is a finding.

## Response

Confirmed DCSync = all domain credentials compromised: plan full AD credential reset including **krbtgt twice**, service accounts, and trust keys (`eradication-recovery`).

## Related skills

`credential-theft-detection`, `kerberos-attack-detection`, `ad-attack-path-analysis`, `zeek-log-analysis`

## References

- MITRE ATT&CK T1003.006: https://attack.mitre.org/techniques/T1003/006/
- MITRE ATT&CK T1207: https://attack.mitre.org/techniques/T1207/
- Microsoft event 4662: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662
