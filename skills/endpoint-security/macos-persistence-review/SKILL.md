---
name: macos-persistence-review
description: Review macOS persistence and privilege surfaces — LaunchAgents/Daemons, Background Task Management login items, cron, configuration profiles, login/logout hooks, authorization plugins, browser extensions and TCC grants. Use when sweeping Macs for malware persistence, verifying cleanup, or auditing endpoint configuration.
license: MIT
metadata:
  category: endpoint-security
  version: "2.0.0"
  verification: documented
---

# macOS Persistence Review

## Locations

| Mechanism | Path / command | Notes |
|---|---|---|
| Launch agents (user) | `~/Library/LaunchAgents/*.plist` | Most common malware persistence |
| Launch agents (all users) | `/Library/LaunchAgents/*.plist` | |
| Launch daemons (root) | `/Library/LaunchDaemons/*.plist` | |
| BTM / Login items | `sudo sfltool dumpbtm` | macOS 13+ consolidated view |
| Cron / periodic | `crontab -l`, `/usr/lib/cron/tabs/`, `/etc/periodic/` | |
| Profiles | `profiles list -all`, `profiles show -type configuration` | Malicious profiles set proxies/DNS/root CAs |
| Authorization plugins | `/Library/Security/SecurityAgentPlugins/` | Credential capture |
| Login/logout hooks (legacy) | `defaults read com.apple.loginwindow` | |
| Kernel/system extensions | `systemextensionsctl list`, `kmutil showloaded` | |
| Shell rc | `~/.zshrc`, `~/.zprofile`, `/etc/zshrc` | |
| Browser extensions | Chrome/Safari extension dirs | Adware/stealers |

## Inspect a plist

```sh
plutil -p ~/Library/LaunchAgents/com.example.updater.plist     # ProgramArguments, RunAtLoad, KeepAlive
codesign -dvvv "$(plutil -extract ProgramArguments.0 raw ~/Library/LaunchAgents/com.example.updater.plist)"
```
Red flags: `ProgramArguments` pointing into `/tmp`, `/Users/Shared`, `~/Library/Application Support/<random>`, hidden directories; interpreters (`/bin/bash -c`, `python3`, `osascript`) with inline payload; ad-hoc/unsigned binaries; labels imitating Apple (`com.apple.*` outside `/System`).

## TCC review

```sh
sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT service, client, auth_value, datetime(last_modified,'unixepoch') FROM access WHERE auth_value=2 ORDER BY last_modified DESC;"
```
(`auth_value=2` = allowed.) Unexpected `kTCCServiceSystemPolicyAllFiles` (Full Disk Access), `kTCCServiceScreenCapture`, `kTCCServiceAccessibility` grants to non-enterprise apps are high risk. Schema varies across macOS releases.

## Tools

Objective-See **KnockKnock** (persistence enumeration), **BlockBlock** (real-time persistence alerts); osquery `launchd`, `startup_items` tables.

## Related skills

`macos-triage`, `osquery-investigation`, `mdm-compliance-review`

## References

- Apple: Script management with launchd: https://support.apple.com/guide/terminal/script-management-with-launchd-apdc6c1077b-5d5d-4d35-9c19-60f2397b2369/mac
- Objective-See KnockKnock: https://objective-see.org/products/knockknock.html
- MITRE ATT&CK T1543.001 Launch Agent: https://attack.mitre.org/techniques/T1543/001/
