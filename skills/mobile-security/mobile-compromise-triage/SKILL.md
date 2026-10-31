---
name: mobile-compromise-triage
description: Triage suspected iOS or Android device compromise — spyware (mercenary/commercial spyware indicators), malicious profiles and MDM enrollment, sideloaded or malicious apps, account takeover via the phone — using Mobile Verification Toolkit (MVT), sysdiagnose, Android bugreports and MDM data, with careful evidence handling. Use when a user (especially executives, journalists or high-risk staff) suspects their phone is compromised or receives an Apple threat notification.
license: MIT
metadata:
  category: mobile-security
  version: "2.0.0"
  verification: documented
---

# Mobile Compromise Triage

## Intake

- Device, OS version, ownership (corporate/BYOD), MDM status, symptoms, Apple/Google threat notifications (Apple sends "threat notifications" for state-sponsored mercenary spyware — treat seriously), recent suspicious messages/links.
- Consent and privacy: personal devices require user consent; collect only what's needed; involve legal for BYOD.

## Collection

iOS:
```sh
# Encrypted local backup (preferred for MVT), via Finder/iTunes or libimobiledevice:
idevicebackup2 backup --full ./backup        # set backup encryption password first
mvt-ios decrypt-backup -p '<password>' -d ./decrypted ./backup
mvt-ios check-backup --iocs ./iocs/ -o ./mvt-out ./decrypted
# sysdiagnose (Settings > Privacy > Analytics or button combo) contains logs useful to MVT and analysts
```
Android:
```sh
mvt-android check-adb -o ./mvt-out --iocs ./iocs/          # requires USB debugging (temporarily)
adb bugreport ./bugreport.zip ; mvt-android check-bugreport --iocs ./iocs/ -o ./mvt-out ./bugreport.zip
mvt-android download-apks -o ./apks                        # then review apps
```
IOCs: Amnesty Tech / Citizen Lab published STIX indicators (`mvt-ios download-iocs` / `mvt-android download-iocs`).

## Commodity threats (more common)

Malicious configuration profiles or rogue MDM enrollment (Settings → General → VPN & Device Management), sideloaded apps / enterprise certificates, Android accessibility-abusing banking trojans, SIM swap (sudden loss of service), account takeover of Apple ID/Google account, stalkerware.

## Response

High-risk user: replace device, enable Lockdown Mode (iOS) / Advanced Protection (Android), rotate account credentials from a clean device, review cloud account sessions. Commodity: remove profile/app, update OS, reset device if in doubt, rotate passwords/sessions for corporate accounts used on it. Engage specialist help (e.g., Access Now helpline for civil society) for mercenary spyware cases.

## Related skills

`mdm-compliance-review`, `account-compromise-investigation`, `evidence-intake`

## References

- Mobile Verification Toolkit (MVT): https://docs.mvt.re/
- Apple threat notifications: https://support.apple.com/en-us/102174
- Apple Lockdown Mode: https://support.apple.com/en-us/105120
- NIST SP 800-101 Rev. 1 Guidelines on Mobile Device Forensics: https://csrc.nist.gov/pubs/sp/800/101/r1/final
