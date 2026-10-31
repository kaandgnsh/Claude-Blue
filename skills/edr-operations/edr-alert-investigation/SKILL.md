---
name: edr-alert-investigation
description: Investigate an EDR alert (Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Elastic Defend, Sophos, etc.) end to end — process lineage, file origin, network activity, user context, prevalence and related alerts — to a verdict and response. Use when working an endpoint detection, or when an EDR incident groups multiple alerts.
license: MIT
metadata:
  category: edr-operations
  version: "2.0.0"
  verification: documented
---

# EDR Alert Investigation

## Workflow

1. **Understand the detection**: vendor detection name, tactic/technique, whether it was *prevented* or only *detected*. Prevented ≠ resolved: the delivery and any pre-block activity still matter.
2. **Process lineage** (`process-tree-analysis`): from the initial process up to the user session (explorer/winlogon/sshd/launchd) and down to all children.
3. **File origin**: who wrote the file, from where (browser download, email client temp, archive extraction, SMB share, USB), Mark-of-the-Web / quarantine attributes, first seen in org.
4. **Network**: DNS and connections from the process tree ±30 min; new or rare domains; data volumes.
5. **User & host context**: user role, recent sign-ins (`account-compromise-investigation`), host criticality, sensor health.
6. **Prevalence**: same hash/command line/domain elsewhere in fleet.
7. **Related alerts**: email, identity, cloud alerts on same user/host.
8. **Verdict & response**: TP → `host-isolation` / `containment-plan`; BTP → document; FP → `alert-tuning` + vendor FP submission.

## Product query examples

Microsoft Defender XDR (Advanced Hunting):
```kusto
let dev = "<DeviceName>"; let t = datetime(<alert time>);
DeviceProcessEvents
| where DeviceName =~ dev and Timestamp between ((t - 1h) .. (t + 1h))
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, SHA256
| order by Timestamp asc
```
File origin: `DeviceFileEvents | where SHA256 == "<sha256>" | project Timestamp, DeviceName, FolderPath, FileOriginUrl, FileOriginReferrerUrl, InitiatingProcessFileName`

CrowdStrike Falcon (Event Search / LogScale, field names per Falcon schema):
```
#event_simpleName=ProcessRollup2 aid=<aid> | table([@timestamp, ParentBaseFileName, FileName, CommandLine, SHA256HashData])
```
SentinelOne Deep Visibility / PowerQuery and Elastic Defend (`process.parent.name`, `process.command_line` in ECS) have equivalent pivots — confirm syntax in your console version.

## Pitfalls

- Investigating only the alerted process, not its parent chain and siblings.
- Concluding "blocked, nothing to do" without checking for persistence or credential access before the block.
- Ignoring sensor gaps (tamper, offline periods) in the timeline.

## Output

Use the `alert-triage` template plus: detection name/ID, prevention status, process tree summary, file origin, network IOCs, prevalence count, response actions taken.

## Related skills

`process-tree-analysis`, `alert-triage`, `host-isolation`, `live-response`, `ioc-assessment`

## References

- Microsoft Defender XDR advanced hunting schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
- CrowdStrike, SentinelOne and Elastic product documentation (vendor portals; require customer access)
- Elastic Common Schema: https://www.elastic.co/guide/en/ecs/current/index.html
