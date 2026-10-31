---
name: radius-log-investigation
description: Investigate network access authentication using RADIUS/NPS/ISE/ClearPass/FreeRADIUS logs — 802.1X Wi-Fi and wired access, VPN authentication, failure reasons, MAC authentication bypass abuse, accounting records (session start/stop, IP, bytes) — to attribute devices and users to network sessions. Use when tracing who was on the network at a time, investigating authentication failures or spoofed MAB devices, or correlating network sessions with incidents.
license: MIT
metadata:
  category: wireless-security
  version: "2.0.0"
  verification: documented
---

# RADIUS Log Investigation

## Sources

| Server | Logs |
|---|---|
| Microsoft NPS | Windows Security log **6272** (granted), **6273** (denied, with Reason Code), 6274–6278; NPS accounting logs (IAS/database format) |
| Cisco ISE | Live Logs / RADIUS authentication and accounting reports, syslog to SIEM |
| Aruba ClearPass | Access Tracker, syslog |
| FreeRADIUS | `radius.log` (`Login OK`/`Login incorrect`), `detail` files per NAS (accounting) |

## Key attributes

`User-Name`, `Calling-Station-Id` (client MAC), `Called-Station-Id` (AP/BSSID:SSID or switch port), `NAS-IP-Address`/`NAS-Identifier`, `NAS-Port-Id`, `Framed-IP-Address` (accounting), `Acct-Status-Type` (Start/Stop/Interim-Update), `Acct-Session-Id`, `Acct-Input/Output-Octets`, EAP type, authorization profile/VLAN.

## Questions & queries

- **Who had IP X at time T?** Accounting Start/Interim records with `Framed-IP-Address` = X around T → `User-Name` + MAC (also cross-check DHCP logs).
  ```spl
  index=radius Acct-Status-Type IN (Start, Interim-Update) Framed-IP-Address="10.20.30.40" earliest="03/01/2025:09:00:00" latest="03/01/2025:11:00:00"
  | table _time, User-Name, Calling-Station-Id, NAS-Identifier, Called-Station-Id, Acct-Session-Id
  ```
- **Failures spike**: NPS 6273 reason codes (e.g., 16 = authentication failed due to credentials mismatch, 48 = no matching network policy, 265 = certificate chain issue) — mass failures from one AP may indicate evil twin activity nearby or misconfiguration.
- **MAB abuse**: MAC Authentication Bypass profiles (printers, IoT) used by a device whose profiling (DHCP fingerprint, user agent) doesn't match — MAC spoofing to get on the network. Check endpoint profiling changes in ISE/ClearPass.
- **VPN**: RADIUS/LDAP auth for VPN logins from unusual locations; link to `account-compromise-investigation`.

## Output

`Time UTC | User | MAC | NAS/AP/port | SSID/VLAN | IP | Result/reason | Session ID | Notes`

## Related skills

`enterprise-wifi-review`, `rogue-ap-detection`, `incident-scoping`, `windows-event-log-analysis`

## References

- RFC 2865 RADIUS: https://www.rfc-editor.org/rfc/rfc2865
- RFC 2866 RADIUS Accounting: https://www.rfc-editor.org/rfc/rfc2866
- Microsoft Audit Network Policy Server (events 6272–6280): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-network-policy-server
- FreeRADIUS documentation: https://www.freeradius.org/documentation/
