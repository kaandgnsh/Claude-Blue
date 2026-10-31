---
name: stack-counting-hunt
description: Hunt by stacking (frequency analysis / long-tail analysis) — count process paths, parent-child pairs, autoruns, services, user agents, DNS domains or scheduled tasks across the fleet to surface rare outliers. Use when looking for unknown malware or persistence without specific IOCs, or establishing baselines.
license: MIT
metadata:
  category: threat-hunting
  version: "2.0.0"
  verification: documented
---

# Stack Counting (Long-Tail) Hunt

Malware is usually rare; legitimate software is usually common. Count an attribute across many hosts and inspect the tail.

## Good stacking attributes

| Attribute | Data |
|---|---|
| Process image path + signer | EDR process events |
| Parent → child image pair | EDR / Sysmon 1 |
| Service name + binary path | 7045, `services` inventory |
| Scheduled task name + action | 4698, task inventory |
| Autorun entries | Autoruns, osquery `startup_items` |
| DLLs loaded by sensitive processes | Sysmon 7 (lsass, explorer) |
| Named pipes | Sysmon 17/18 |
| Outbound domains per process | Sysmon 22 / proxy |
| HTTP user agents | Proxy logs |
| Listening ports | osquery `listening_ports` |

## Queries

Sentinel (MDE): rare parent/child pairs across ≤3 devices in 30 days
```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| summarize devices=dcount(DeviceId), sample=any(ProcessCommandLine) by InitiatingProcessFileName, FileName, FolderPath
| where devices <= 3
| order by devices asc
```
Splunk: rare service binaries
```spl
index=wineventlog EventCode=7045 earliest=-30d
| stats dc(host) as hosts values(host) as hostlist by Service_Name, Service_File_Name
| where hosts <= 2 | sort hosts
```

## Method

1. Normalize values (lowercase paths, replace user names/GUIDs/version numbers with placeholders) so the same software doesn't look rare: e.g. `C:\Users\<user>\AppData\Local\...`.
2. Count by **distinct hosts**, not events.
3. Review the bottom 1–5%; for each: signer, hash reputation, path, first seen, which hosts and users.
4. Record benign tail items in a baseline lookup so future hunts skip them (with review date).

## Pitfalls

- Per-user install paths and auto-updating software (Teams, Chrome, Zoom) dominate the tail unless normalized.
- Targeted intrusions touching one host look like noise — combine with crown-jewel scoping.
- Attackers who masquerade as common binaries (correct name, wrong path/hash) → stack name+path+hash together.

## Related skills

`hypothesis-hunt`, `windows-persistence-hunt`, `osquery-investigation`, `hunt-to-detection`

## References

- SANS "Stacking" hunting technique (FOR508 materials, blogs): https://www.sans.org/blog/
- MITRE ATT&CK T1036 Masquerading: https://attack.mitre.org/techniques/T1036/
