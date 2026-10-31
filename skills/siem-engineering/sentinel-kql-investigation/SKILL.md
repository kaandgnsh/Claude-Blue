---
name: sentinel-kql-investigation
description: Write KQL for Microsoft Sentinel and Defender XDR advanced hunting — table selection (SigninLogs, AuditLogs, SecurityEvent, Device* tables, OfficeActivity, AzureActivity), summarize/join/make_set, time windows, parsing dynamic JSON, watchlists — with correctness and cost awareness. Use when investigating or hunting in Sentinel/Log Analytics or Defender XDR.
license: MIT
metadata:
  category: siem-engineering
  version: "2.0.0"
  verification: documented
---

# KQL Investigation (Sentinel / Defender XDR)

## Table map

| Data | Sentinel (Log Analytics) | Defender XDR advanced hunting |
|---|---|---|
| Entra sign-ins | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs` | `EntraIdSignInEvents` (former `AADSignInEventsBeta`) |
| Entra directory changes | `AuditLogs` | `CloudAppEvents` (partial) |
| Windows Security log | `SecurityEvent` / `WindowsEvent` | — |
| Endpoint (MDE) | `Device*` tables if streamed | `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceEvents` |
| M365 audit | `OfficeActivity` | `CloudAppEvents` |
| Email | — | `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `EmailPostDeliveryEvents`, `UrlClickEvents` |
| Azure control plane | `AzureActivity` | — |
| Alerts | `SecurityAlert`, `SecurityIncident` | `AlertInfo`, `AlertEvidence` |

Table names evolve; confirm in the schema pane. Defender XDR uses `Timestamp`, Sentinel uses `TimeGenerated`.

## Patterns

```kusto
// Filter early on time and indexed columns, then project
SigninLogs
| where TimeGenerated between (datetime(2025-03-01) .. datetime(2025-03-08))
| where UserPrincipalName =~ "alice@contoso.com"
| project TimeGenerated, IPAddress, AppDisplayName, ResultType, ResultDescription,
          Location = tostring(LocationDetails.countryOrRegion), DeviceId = tostring(DeviceDetail.deviceId),
          UserAgent, ConditionalAccessStatus, AuthenticationRequirement

// Parse dynamic JSON from AuditLogs
AuditLogs
| where OperationName has "Add member to role"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName),
         Target = tostring(TargetResources[0].userPrincipalName),
         Role = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue)

// Join sign-in to device process activity within 10 minutes
let ips = SigninLogs | where ResultType == 0 and RiskLevelDuringSignIn in ("medium","high") | distinct IPAddress;
DeviceNetworkEvents | where RemoteIP in (ips)

// Watchlist enrichment
let vip = _GetWatchlist('VIPUsers') | project SearchKey;
SigninLogs | where UserPrincipalName in~ (vip)
```

## Correctness traps

- `has` matches whole terms (fast); `contains` substrings (slow); `==` is case-sensitive, `=~` insensitive.
- `join` default kind is `innerunique` (deduplicates left side!) — specify `kind=inner` or `leftouter` explicitly.
- `make_set()` default limit 1048576 but consider passing a cap; `take`/`limit` returns arbitrary rows — not "latest".
- `ResultType` in SigninLogs is a **string** (`"0"` success); compare as string or `toint()`.
- Non-interactive sign-ins (token refresh) are in a separate table — attackers using stolen refresh tokens appear there.
- Retention: Analytics tier vs. Basic/Auxiliary logs (limited KQL, extra query cost) vs. archive (search jobs/restore).

## Related skills

`entra-signin-investigation`, `edr-alert-investigation`, `query-performance`, `sigma-conversion`

## References

- KQL reference: https://learn.microsoft.com/en-us/kusto/query/
- Defender XDR advanced hunting schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
- Azure Monitor table reference: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables-index
- Microsoft Sentinel hunting queries (GitHub): https://github.com/Azure/Azure-Sentinel
