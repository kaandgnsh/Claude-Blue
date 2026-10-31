---
name: macos-triage
description: Triage a potentially compromised Mac — unified logs, running processes and code signatures, quarantine attributes, network connections, TCC permissions, installed profiles and persistence — using built-in tools and Aftermath/mac_apt. Use when investigating macOS malware alerts (infostealers, adware, backdoors), suspicious logins, or MDM/EDR detections on Apple endpoints.
license: MIT
metadata:
  category: endpoint-security
  version: "2.0.0"
  verification: documented
---

# macOS Triage

## Collection

```sh
sudo log collect --last 3d --output ~/Desktop/host.logarchive     # unified log archive (preserve)
ps -axo pid,ppid,user,lstart,command > ps.txt
lsof -i -n -P > lsof_net.txt
sudo sfltool dumpbtm > btm.txt                                     # Background Task Management items (macOS 13+)
profiles list -all > profiles.txt 2>&1                             # configuration profiles (malicious MDM/proxy profiles)
ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons > launchd_ls.txt
```
Aftermath (Jamf, open source) and mac_apt automate collection/parsing; Velociraptor and osquery also support macOS.

## Checks

| Question | Command |
|---|---|
| Signed/notarized? | `codesign -dvvv /path/to/App.app`; `spctl -a -vvv -t exec /path/to/App.app` |
| Where did it come from? | `xattr -l file` (`com.apple.quarantine`, `com.apple.metadata:kMDItemWhereFroms`); `sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 'select * from LSQuarantineEvent'` |
| Platform protections | `csrutil status` (SIP), `spctl --status` (Gatekeeper), `fdesetup status` (FileVault) |
| Privacy grants | TCC DBs: `~/Library/Application Support/com.apple.TCC/TCC.db`, `/Library/Application Support/com.apple.TCC/TCC.db` (needs Full Disk Access) — see `macos-persistence-review` |
| Recent logins / auth | `log show --archive host.logarchive --predicate 'process == "loginwindow" OR process == "sshd" OR eventMessage CONTAINS "authentication"' --style syslog` |
| Executions blocked by XProtect/Gatekeeper | `log show --predicate 'subsystem == "com.apple.xprotect" OR process == "syspolicyd"' --last 3d` |

## Infostealer pattern (common in 2024–2026)

Unsigned/ad-hoc signed app from a fake download or cracked software → `osascript` prompting for the user password (`display dialog ... with hidden answer`) → access to Keychain, browser profiles (`~/Library/Application Support/Google/Chrome/`), crypto wallets → zip and HTTP POST exfil. Hunt: `osascript` child of an app in `/Volumes/` or `~/Downloads`; `curl -X POST` with zip uploads; access to `login.keychain-db` by non-Apple processes.

## Response

Assume browser session cookies, saved passwords and keychain secrets are stolen: revoke sessions and rotate credentials (`token-theft-investigation`), not just remove the malware.

## Related skills

`macos-persistence-review`, `osquery-investigation`, `token-theft-investigation`, `mdm-compliance-review`

## References

- Apple Platform Security guide: https://support.apple.com/guide/security/welcome/web
- Jamf Aftermath: https://github.com/jamf/aftermath
- mac_apt: https://github.com/ydkhatri/mac_apt
- Objective-See tools and malware write-ups: https://objective-see.org/
