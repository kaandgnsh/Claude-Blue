---
name: process-tree-analysis
description: Reconstruct and judge process trees — expected Windows/Linux/macOS parent-child relationships, Office/browser spawning shells, LOLBin chains, injection and PPID spoofing — to separate malicious execution from normal software behaviour. Use when an alert includes a process, when reviewing EDR process graphs, or when hunting suspicious lineage.
license: MIT
metadata:
  category: edr-operations
  version: "2.0.0"
  verification: documented
---

# Process Tree Analysis

## Known-good Windows lineage (abbreviated)

| Process | Expected parent | Notes |
|---|---|---|
| `smss.exe` | System | one master instance |
| `wininit.exe`, `csrss.exe` | smss.exe (exits) | |
| `services.exe`, `lsass.exe` | wininit.exe | only one lsass, path `C:\Windows\System32` |
| `svchost.exe` | services.exe | always `-k <group>` |
| `winlogon.exe` | smss.exe (exits) | |
| `userinit.exe` → `explorer.exe` | winlogon.exe | userinit exits |
| `taskhostw.exe` | svchost.exe (Schedule) | |
| `WmiPrvSE.exe` | svchost.exe (DcomLaunch) | WMI child processes |
| `wsmprovhost.exe` | svchost.exe | PowerShell remoting |

## Suspicious patterns

| Pattern | Why |
|---|---|
| `winword.exe`/`excel.exe`/`outlook.exe` → `cmd`/`powershell`/`wscript`/`mshta`/`rundll32` | Macro/exploit execution (T1204.002) |
| Browser → script host or LOLBin directly | Drive-by / HTML smuggling |
| `explorer.exe` → `mshta.exe`/`wscript.exe` with a file from `Downloads`/`Temp`/`.lnk` | User-executed payload (ISO/ZIP/LNK chains) |
| `w3wp.exe`, `httpd`, `nginx`, `java` (Tomcat), `node` → shell | Web shell / RCE |
| `services.exe` → random-named exe from `ADMIN$`/`C:\Windows\` | PsExec-style lateral movement |
| `WmiPrvSE.exe` → `powershell -enc` | WMI execution |
| `sqlservr.exe` → `cmd.exe` | xp_cmdshell |
| `rundll32.exe` without DLL argument, or with `javascript:` | Abuse/injection host |
| `svchost.exe` not from System32, or without `-k` | Masquerading |
| Process with parent that exited long ago and unusual PPID | Possible PPID spoofing — check `CreatorProcessId` / EDR "real parent" fields |

Linux: `sshd` → `bash` normal; `www-data` or Java app → `sh -c` + `curl|wget|base64` suspicious; `cron` → binary in `/tmp`. macOS: `launchd` parents most apps; `osascript` from an app in `/Volumes` or `~/Downloads` is suspicious.

## Method

1. Walk up to the session root; note user, logon ID, integrity level.
2. Walk down: all children/grandchildren, including short-lived ones (they often hold the interesting command line).
3. For each node: image path, signer, hash prevalence, command line, network/file/registry actions.
4. Compare to fleet baseline: `stack-counting-hunt` on parent→child pairs.
5. Summarize as an indented tree with timestamps.

## Output

```
<t> explorer.exe (user CORP\alice, pid 4120)
  <t> WINWORD.EXE invoice.docm
    <t> cmd.exe /c powershell -enc JAB...   ← decoded: IEX download from hxxp://...
      <t> powershell.exe → connects 198.51.100.7:443
```

## Related skills

`edr-alert-investigation`, `lolbin-hunt`, `script-deobfuscation`, `memory-forensics`

## References

- SANS "Hunt Evil" poster: https://www.sans.org/posters/hunt-evil/
- MITRE ATT&CK T1134.004 Parent PID Spoofing: https://attack.mitre.org/techniques/T1134/004/
