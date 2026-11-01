---
name: attack-simulation-safety
description: Run attack simulation tools (Atomic Red Team, MITRE Caldera, Stratus Red Team, BAS agents) without harming production, covering test prerequisites review, isolation of test identities and hosts, alert routing, dependency and side-effect checks, cleanup commands and post-test verification that nothing is left behind. Use when about to execute emulation in a corporate or cloud environment, when reviewing an atomic test before running it, or after a test left artifacts or caused an outage.
license: MIT
metadata:
  category: security-testing
  version: "2.2.0"
  verification: documented
---

# Attack Simulation Safety

Emulation tools run real attacker techniques. Atomic tests create services, add registry run keys, dump LSASS, change cloud IAM, and some disable security tools. Read every test before running it, and prove cleanup afterwards.

## 1. Review each test before execution

For every atomic/ability/procedure fill in:

| Item | Check |
|---|---|
| What it changes | Files, registry, services, scheduled tasks, accounts, cloud resources, security settings |
| Privileges | User / admin / SYSTEM / cloud role required |
| Network | Does it download from the internet (GitHub raw, tool sites)? Does it contact external IPs? |
| Destructive potential | Deletes shadow copies, stops services, encrypts files, modifies firewall, disables Defender |
| Cleanup | Is there a cleanup command, and does it fully revert (e.g., removes the service *and* the binary)? |
| Dependencies | Prerequisite installs (Python, Mimikatz, Sysinternals) that persist after the test |

```powershell
# Invoke-AtomicRedTeam: read details, check prerequisites, then run and clean up
Invoke-AtomicTest T1547.001 -ShowDetailsBrief
Invoke-AtomicTest T1547.001 -TestNumbers 1 -ShowDetails
Invoke-AtomicTest T1547.001 -TestNumbers 1 -CheckPrereqs
Invoke-AtomicTest T1547.001 -TestNumbers 1
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```

Reject or adapt tests that: disable or uninstall security tooling on shared hosts, delete backups/shadow copies (T1490), encrypt real data (T1486), or change domain-wide settings (GPO, trusts). Emulate these on isolated lab replicas.

## 2. Isolation

- Dedicated test hosts that mirror production builds and agents but hold no production data; tag them in CMDB/SIEM.
- Dedicated test accounts with expiry dates, never real users' accounts. For cloud, a dedicated test subscription/account/project inside the real organization (so org-level detections and policies apply).
- Pin test sources: test IP ranges or runner hostnames recorded in the deconfliction sheet.
- Stage tools from an internal share rather than downloading from the internet during the test (avoids accidental fetch of modified payloads).

## 3. Alert routing

- Route alerts for test entities to the exercise channel, not suppress them: suppression hides results and can leak into production rules if left in place.
- If a temporary exclusion is unavoidable, give it an expiry and a ticket, and list it in the cleanup checklist.
- Brief on-call: "alerts from hosts tagged `purple-team` between 09:00-17:00 UTC are expected; anything from other hosts is real".

## 4. Stop conditions during execution

Stop and call the exercise lead if: a non-test host shows related activity, a service outage appears on a dependency, the tool behaves differently than reviewed (unexpected network destination), or evidence of a real intrusion appears. Real incident handling takes priority; preserve test logs for deconfliction.

## 5. Cleanup and verification

Do not trust cleanup commands alone. Verify with independent queries:

```kusto
// Defender for Endpoint: persistence and services created on test hosts during the window
union DeviceRegistryEvents, DeviceEvents, DeviceProcessEvents
| where Timestamp between (datetime(2026-10-30T09:00:00Z) .. datetime(2026-10-30T18:00:00Z))
| where DeviceName in~ ("ws-pt1", "srv-pt2")
| where (ActionType == "RegistryValueSet" and RegistryKey has @"\CurrentVersion\Run")
     or ActionType in ("ServiceInstalled", "ScheduledTaskCreated", "UserAccountCreated")
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, FileName, ProcessCommandLine
```

Cleanup checklist:

- [ ] Persistence removed (run keys, services, scheduled tasks, WMI subscriptions, startup folder).
- [ ] Created accounts and group memberships removed; test account passwords rotated or accounts disabled.
- [ ] Tools and dropped files removed (prerequisite installs too); hashes recorded for later search.
- [ ] Cloud resources/roles/keys created by tests deleted (Stratus Red Team: `stratus cleanup --all`).
- [ ] Temporary exclusions/suppressions removed.
- [ ] Hosts re-imaged when tests touched security tooling or credentials (LSASS dumps on a host = treat its cached credentials as exposed).
- [ ] Written confirmation stored with the exercise report.

## Related skills

`security-test-planning`, `purple-team-exercise`, `detection-testing`, `detection-validation`, `control-validation`, `windows-persistence-hunt`

## References

- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- Invoke-AtomicRedTeam wiki: https://github.com/redcanaryco/invoke-atomicredteam/wiki
- Stratus Red Team: https://stratus-red-team.cloud/
- MITRE Caldera documentation: https://caldera.readthedocs.io/
