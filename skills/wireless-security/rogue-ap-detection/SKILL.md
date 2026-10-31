---
name: rogue-ap-detection
description: Detect and handle rogue and evil-twin access points, unauthorized wireless bridges and hotspots using WLAN controller/WIPS data, wired-side correlation (switch MAC tables, NAC), and authorized RF surveys with Kismet — and decide on containment lawfully. Use when WIPS reports rogue APs, users report suspicious SSIDs, or performing periodic wireless audits (e.g., PCI DSS 11.2).
license: MIT
metadata:
  category: wireless-security
  version: "2.0.0"
  verification: documented
---

# Rogue AP Detection

## Classify what you find

| Class | Description | Risk |
|---|---|---|
| Rogue (wired) | Unauthorized AP plugged into your network | High — bypasses perimeter |
| Evil twin | Broadcasts your SSID (or a lookalike) to lure clients | High — credential theft (esp. PEAP without cert validation) |
| Neighbor | Nearby legitimate networks | Ignore (classify as friendly/external) |
| Ad-hoc / hotspot | Phones/laptops sharing connections, Wi-Fi Direct | Medium — policy + bridging risk |
| Misconfigured internal | Corporate AP with wrong config | Medium |

## Detection sources

- WLAN controller / WIPS (Cisco, Aruba, Juniper Mist, Meraki): rogue AP lists with RSSI, detecting APs, channel, SSID, BSSID, and **"rogue on wire"** detection (correlating wireless BSSIDs to wired MACs).
- Wired side: switch CAM tables (`show mac address-table`), NAC/802.1X failures on access ports, DHCP leases from unknown vendor OUIs.
- RF survey (authorized): Kismet with a monitor-mode adapter (`kismet -c wlan0mon`), noting SSIDs, BSSIDs, encryption, clients; locate with directional antenna by RSSI.

## Evil-twin checks

Same SSID but BSSID not in your AP inventory, different security (open vs. WPA2-Enterprise), different channel/vendor OUI, clients reporting certificate warnings. Prevent with **EAP-TLS** or properly configured PEAP with server certificate validation and pinned server names (`enterprise-wifi-review`).

## Response

1. Locate (RSSI triangulation via multiple APs; wired port via MAC table).
2. Wired rogue: disable switch port (change process), retrieve device, identify owner.
3. Evil twin: warn users, check RADIUS for failed/unusual authentications, reset credentials of users who connected (if credential capture possible).
4. **Wireless containment/deauthentication** of rogue APs may be illegal in some jurisdictions (e.g., US FCC has fined deauthentication of others' networks) — only contain APs on your own wired network and per legal guidance.

## Related skills

`enterprise-wifi-review`, `radius-log-investigation`, `network-segmentation-review`

## References

- NIST SP 800-153 Guidelines for Securing WLANs: https://csrc.nist.gov/pubs/sp/800/153/final
- Kismet: https://www.kismetwireless.net/docs/
- PCI DSS v4.0.1 Requirement 11.2 (wireless access point testing): https://www.pcisecuritystandards.org/document_library/
