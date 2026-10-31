---
name: incident-scoping
description: Determine the full scope of a compromise — patient zero, initial access vector, affected hosts, identities, data and persistence — using IOC and TTP pivots across telemetry. Use when an incident is confirmed and you must answer "how far did it spread?" before containment or eradication.
license: MIT
metadata:
  category: incident-response
  version: "2.0.0"
  verification: documented
---

# Incident Scoping

Contain too early and the attacker keeps footholds you never found; contain too late and they spread. Scoping is iterative: find → pivot → re-find until no new entities appear.

## Pivot loop

1. **Seed list**: everything known (hosts, accounts, IPs, domains, hashes, file names, service names, scheduled task names, mailbox rules, cloud keys).
2. **Sweep each indicator across all telemetry** with the widest retention available:
   - Hash prevalence (MDE): `DeviceFileEvents | where SHA256 in (<hashes>) | summarize first=min(Timestamp), hosts=dcount(DeviceId) by SHA256`
   - Network: `DeviceNetworkEvents | where RemoteIP in (<ips>) or RemoteUrl has_any (<domains>) | summarize min(Timestamp), make_set(DeviceName) by RemoteIP, RemoteUrl`
   - Splunk: `index=* (<ioc1> OR <ioc2>) earliest=-90d | stats min(_time) max(_time) values(host) by sourcetype`
   - Identity: every logon by compromised accounts: `SigninLogs | where UserPrincipalName in (<upns>) | summarize by IPAddress, AppDisplayName, DeviceDetail.deviceId, ResultType`
3. **Sweep TTPs, not just IOCs** — attackers rotate hashes and IPs. Search for the *behaviour*: same parent→child pattern, same scheduled-task naming, same tool flags, same lateral movement method (e.g. 4624 type 3 + service install 7045 within 2 minutes).
4. **Add new entities** to the seed list; repeat until a pass finds nothing new.
5. **Determine initial access** by working backward from the earliest artifact (phish, VPN logon, exploited service, stolen token, supply chain).
6. **Inventory persistence**: services, tasks, run keys, WMI subscriptions, new accounts, MFA methods added, OAuth consents, mailbox rules, cloud access keys, federation/trust changes, web shells.
7. **Assess data exposure**: what did compromised identities access (file audit, SharePoint/OneDrive `FileAccessed`, S3 data events, database audit)?

## Scope statement

Express scope with confidence and telemetry coverage, e.g. "12 hosts confirmed, 3 likely; 2 accounts confirmed. Coverage: EDR on 94% of Windows servers, no EDR on Linux web tier (gap)".

## Output template

```
Scope as of <UTC>   Iteration: <n>
Initial access: <vector> (confidence)   Patient zero: <host/user> at <t>
Hosts: confirmed <list> | likely <list>
Identities: <list> (incl. service accounts, cloud principals)
Persistence found: <list with location>
Data accessed/exfiltrated: <evidence>
Telemetry gaps: <>
Next pivots: <>
```

## Safety

Read-only sweeps. Coordinate timing of any visible action (password resets, isolations) with the IC so all footholds are removed simultaneously.

## Related skills

`containment-plan`, `timeline-analysis`, `velociraptor-collection`, `osquery-investigation`, `account-compromise-investigation`, `cloud-incident-response`

## References

- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- MITRE ATT&CK: https://attack.mitre.org/
