---
name: kerberos-attack-detection
description: Detect Kerberoasting, AS-REP roasting, golden/silver/diamond tickets, overpass-the-hash and delegation abuse using domain controller events 4768, 4769, 4771 and ticket encryption types. Use when investigating suspicious TGS/TGT requests, RC4 (0x17) tickets, or Kerberos anomalies in Active Directory.
license: MIT
metadata:
  category: active-directory-security
  version: "2.0.0"
  verification: documented
---

# Kerberos Attack Detection

Requires DC auditing: *Audit Kerberos Authentication Service* and *Audit Kerberos Service Ticket Operations* (Success & Failure).

## Encryption types (`TicketEncryptionType`)

`0x11` AES128, `0x12` AES256, `0x17` RC4-HMAC, `0x18` RC4-HMAC-EXP, `0x1`/`0x3` DES. In a modern domain most tickets are AES; RC4 requests for service tickets are the classic Kerberoasting tell.

## Attacks and signals

| Attack | Event | Signal |
|---|---|---|
| Kerberoasting (T1558.003) | 4769 | `TicketEncryptionType=0x17`, service is a **user** account (not `$`), many distinct services by one account in a short window, `TicketOptions` 0x40810000/0x40800000 |
| AS-REP roasting (T1558.004) | 4768 | `PreAuthType=0` for accounts with `DONT_REQ_PREAUTH`; RC4 |
| Password spray via Kerberos | 4771 | `FailureCode=0x18` (bad password) across many users from one IP |
| Golden ticket (T1558.001) | 4769/4624 | Service tickets with no preceding 4768 from that host/user; account names that don't exist; abnormal ticket lifetimes; RC4 when domain is AES-only |
| Silver ticket (T1558.002) | Service host | Logons to a service without any 4769 on DCs (forged TGS never touches the DC) |
| Overpass-the-hash | 4768 | RC4 TGT requested from a workstation for a user who normally gets AES |
| Delegation abuse (S4U) | 4769 | `TransmittedServices` populated; unexpected S4U2Self/S4U2Proxy |

## Queries

Sentinel:
```kusto
SecurityEvent
| where EventID == 4769 and TicketEncryptionType == "0x17"
| where ServiceName !endswith "$" and ServiceName != "krbtgt"
| summarize services=dcount(ServiceName), list=make_set(ServiceName, 50) by TargetUserName, IpAddress, bin(TimeGenerated, 10m)
| where services >= 5
```
Splunk (Windows TA):
```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| bin _time span=10m
| stats dc(Service_Name) as services values(Service_Name) by _time, Account_Name, Client_Address
| where services >= 5
```

## Sigma (single RC4 TGS for a user service account — tune with service allow-list)

```yaml
title: Kerberos RC4 Service Ticket Request for User Account
id: 7c0e4b4a-3f0b-4d36-9a42-5d1b3f2a6e18
status: experimental
description: Detects TGS requests using RC4 encryption for non-machine service accounts, a common Kerberoasting indicator.
author: Claude-Blue
date: 2026-10-31
tags:
  - attack.credential-access
  - attack.t1558.003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    Status: '0x0'
  filter_machine:
    ServiceName|endswith: '$'
  filter_krbtgt:
    ServiceName: 'krbtgt'
  condition: selection and not 1 of filter_*
falsepositives:
  - Legacy applications or service accounts that only support RC4
level: medium
```

## Prevention

Remove SPNs from privileged users; gMSA/dMSA for services (long random passwords); set `msDS-SupportedEncryptionTypes` to AES only and phase out RC4 (Microsoft is disabling RC4 by default — track the current Windows Server guidance); enforce pre-authentication; honey SPN account (`honeytoken-deployment`); reset krbtgt twice after compromise.

## Related skills

`dcsync-detection`, `ad-privileged-access-review`, `password-spray-detection`, `honeytoken-deployment`

## References

- Microsoft 4769 event: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769
- MITRE ATT&CK T1558: https://attack.mitre.org/techniques/T1558/
- Microsoft Kerberos encryption types / RC4 deprecation: https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos
