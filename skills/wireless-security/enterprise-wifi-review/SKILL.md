---
name: enterprise-wifi-review
description: Review enterprise Wi-Fi security — WPA3-Enterprise/WPA2-Enterprise with 802.1X, EAP method choice (EAP-TLS vs. PEAP-MSCHAPv2), supplicant server-certificate validation, PSK networks, guest isolation, management frame protection, segmentation of SSIDs to VLANs, and NAC posture. Use when assessing wireless networks, migrating to certificate-based Wi-Fi, or after evil-twin/credential capture concerns.
license: MIT
metadata:
  category: wireless-security
  version: "2.0.0"
  verification: documented
---

# Enterprise Wi-Fi Review

## Authentication

| Option | Assessment |
|---|---|
| WPA3-Enterprise / WPA2-Enterprise + **EAP-TLS** (device/user certificates via MDM/SCEP) | Preferred: no passwords to phish; mutual authentication |
| PEAP-MSCHAPv2 / EAP-TTLS with passwords | Acceptable only with strict **server certificate validation** pushed to supplicants (trusted CA + server name); otherwise evil twins capture crackable MSCHAPv2 challenges |
| WPA2/WPA3-Personal (PSK/SAE) | For IoT/guest only; unique per-device PSK (iPSK/DPSK) if possible; rotate; WPA3-SAE over WPA2-PSK |
| Open / captive portal | Guest only, fully isolated |

Check supplicant profiles (Intune/GPO/Jamf Wi-Fi profiles): "Verify server identity by validating the certificate", specified server names, specified root CA, no user prompt to trust new servers.

## Configuration checks

- Management Frame Protection (802.11w) required (mandatory in WPA3).
- SSIDs mapped to VLANs with firewall policy (corporate, BYOD, guest, IoT) — guest has internet only, client isolation on.
- Dynamic VLAN/role assignment from RADIUS attributes based on identity and device posture.
- Disable legacy protocols (WEP, TKIP, WPS).
- Controller/AP management interfaces not reachable from client VLANs; firmware current.
- WIPS enabled (`rogue-ap-detection`).
- RADIUS servers redundant, logs forwarded (`radius-log-investigation`).

## Output

`SSID | Purpose | Auth/EAP | Server cert validation enforced | VLAN/segment | Client isolation | MFP | Findings | Recommendation`

## Related skills

`rogue-ap-detection`, `radius-log-investigation`, `network-segmentation-review`, `mdm-compliance-review`

## References

- Wi-Fi Alliance WPA3 specification overview: https://www.wi-fi.org/discover-wi-fi/security
- NIST SP 800-153: https://csrc.nist.gov/pubs/sp/800/153/final
- Microsoft: Configure Wi-Fi with certificate authentication in Intune: https://learn.microsoft.com/en-us/intune/intune-service/configuration/wi-fi-settings-configure
