---
name: memory-forensics
description: Analyze Windows and Linux memory images with Volatility 3 to find malicious processes, injected code, network connections, command lines, persistence and credential-theft artefacts. Use when a memory dump (.raw, .lime, .vmem, hiberfil, crash dump) is available or when fileless malware or process injection is suspected.
license: MIT
metadata:
  category: dfir
  version: "2.0.0"
  verification: documented
---

# Memory Forensics (Volatility 3)

## Setup

```sh
pip install volatility3          # or clone https://github.com/volatilityfoundation/volatility3
vol -f mem.raw windows.info      # confirms symbols/profile load; Linux needs matching ISF symbols
```
Linux images need an ISF symbol file for the exact kernel (`dwarf2json` from vmlinux with debug symbols).

## Triage sequence (Windows)

| Step | Plugin | Look for |
|---|---|---|
| Processes | `windows.pslist`, `windows.psscan`, `windows.pstree` | Hidden processes (in psscan not pslist), wrong parents (e.g. `lsass.exe` not child of `wininit.exe`; `svchost.exe` not child of `services.exe`), misspelled names, odd paths |
| Command lines | `windows.cmdline` | Encoded PowerShell, LOLBins, paths in `%TEMP%`/`AppData` |
| Network | `windows.netscan` | Connections from processes that shouldn't talk (e.g. `notepad.exe`), listeners on unusual ports |
| Injection | `windows.malfind` | `PAGE_EXECUTE_READWRITE` private regions with MZ header or shellcode |
| Modules | `windows.dlllist`, `windows.ldrmodules` | DLLs from user-writable paths; unlinked modules (InLoad/InInit/InMem = False) |
| Services | `windows.svcscan` | Services with binaries in unusual paths or recently added |
| Handles/mutex | `windows.handles --pid N` | Known malware mutexes, handles to `lsass.exe` |
| Registry | `windows.registry.hivelist`, `windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"` | Persistence |
| Files | `windows.filescan`, `windows.dumpfiles --virtaddr 0x...` | Recover binaries/scripts for analysis |
| Process dump | `windows.pslist --pid N --dump`, `windows.memmap --pid N --dump` | Feed to YARA/static analysis |

YARA over memory: `vol -f mem.raw windows.vadyarascan --yara-file rules.yar` (plugin name/options vary by version — check `vol -h`).

## Linux

`linux.pslist`, `linux.pstree`, `linux.bash` (shell history from memory), `linux.lsof`, `linux.sockstat`, `linux.malfind`, `linux.check_modules` / `linux.lsmod` (hidden kernel modules), `linux.elfs`.

## Interpretation

- Baseline parent/child relationships: SANS "Hunt Evil" poster is a practical reference.
- Malfind has false positives (JIT engines: .NET, browsers, Java). Confirm with a dump + YARA/disassembly.
- Correlate memory findings with disk timeline and EDR telemetry; record PID, process create time and virtual addresses.

## Output template

```
Image: <file> sha256 <>  OS: <build>  Captured: <UTC>
Suspicious processes: <pid> <name> <ppid> <path> <reason>
Injection: <pid> <vad addr> <protection> <evidence>
Network: <pid> <local> → <remote> <state>
Persistence: <>
Extracted artefacts: <file> sha256 <>
Confidence & next steps: <>
```

## Safety

Analyse on an isolated analysis workstation. Dumped executables are live malware — store in password-protected archives (`infected`) and never execute outside a sandbox.

## Related skills

`forensic-imaging`, `windows-artifacts`, `yara-authoring`, `credential-theft-detection`, `pe-static-analysis`

## References

- Volatility 3 docs: https://volatility3.readthedocs.io/
- Volatility 3 repository: https://github.com/volatilityfoundation/volatility3
- SANS DFIR "Hunt Evil" poster: https://www.sans.org/posters/hunt-evil/
