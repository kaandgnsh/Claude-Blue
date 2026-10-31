---
name: impossible-travel-review
description: Evaluate impossible-travel and unfamiliar-location alerts correctly — compute travel speed between geolocated sign-ins, account for VPNs, mobile carriers, cloud egress, IPv6 and geo-IP error, and decide compromise vs. benign with corroborating evidence. Use when an impossible travel, atypical travel or new-country sign-in alert needs triage, or when tuning such detections.
license: MIT
metadata:
  category: identity-security
  version: "2.0.0"
  verification: documented
---

# Impossible Travel Review

## Compute

Speed = great-circle distance between consecutive successful sign-ins / time difference. > ~900 km/h (airliner speed) is "impossible"; but geo-IP for VPN/cloud/mobile IPs is often wrong by thousands of km.

```kusto
SigninLogs
| where TimeGenerated > ago(7d) and ResultType == "0" and UserPrincipalName =~ "<upn>"
| extend lat = todouble(LocationDetails.geoCoordinates.latitude), lon = todouble(LocationDetails.geoCoordinates.longitude)
| order by TimeGenerated asc
| extend prevT = prev(TimeGenerated), prevLat = prev(lat), prevLon = prev(lon), prevIP = prev(IPAddress)
| extend km = geo_distance_2points(lon, lat, prevLon, prevLat) / 1000.0, hours = datetime_diff('second', TimeGenerated, prevT) / 3600.0
| extend kmh = iff(hours > 0, km / hours, real(null))
| where kmh > 900
| project TimeGenerated, IPAddress, prevIP, km, hours, kmh, AppDisplayName, DeviceDetail
```

## Benign explanations (verify, don't assume)

| Explanation | How to verify |
|---|---|
| Corporate VPN / ZTNA / SASE egress | IP belongs to your VPN/SASE provider ranges |
| Mobile carrier IP geolocated to carrier HQ | ASN is mobile carrier; device ID matches user's phone |
| Cloud-hosted desktops (AVD/W365/Citrix) | IP in your cloud ranges |
| Same device ID and compliant device on both sign-ins | Device-bound session; still check |
| Real travel | Travel record/HR; first sign-in from new country is plausible |

## Compromise indicators

Different device IDs / OS / browser between the two sign-ins, hosting-provider ASN (VPS, residential proxy services), no MFA or MFA via token claim from the far location, follow-on risky actions (inbox rules, MFA registration, mass downloads).

## Decision

`Benign (explained + evidence)` → tune by adding known egress ranges as named locations; `Suspicious` → `account-compromise-investigation`; `Undetermined` → contact user out of band and force re-authentication.

## Related skills

`entra-signin-investigation`, `account-compromise-investigation`, `alert-tuning`

## References

- Microsoft Defender for Cloud Apps impossible travel: https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- KQL geo_distance_2points: https://learn.microsoft.com/en-us/kusto/query/geo-distance-2points-function
