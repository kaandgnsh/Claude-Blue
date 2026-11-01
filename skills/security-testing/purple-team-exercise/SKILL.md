---
name: purple-team-exercise
description: Plan and run a purple-team exercise where offensive operators and defenders work in the same room on threat-relevant procedures, covering objective and threat selection, procedure list, telemetry checks per step, live tuning, evidence capture and a remediation backlog. Use when organizing a purple-team day or week, turning red-team findings into detections, or validating readiness against a specific threat actor.
license: MIT
metadata:
  category: security-testing
  version: "2.2.0"
  verification: documented
---

# Purple-Team Exercise

The value of purple teaming is the tight loop: run a procedure, look for it together, fix the gap, run it again. Without a written plan it degenerates into a red-team demo; without defenders at the keyboard it is just an audit.

## 1. Objective and threat selection

Pick **one** objective per exercise:

- Readiness against a named threat (e.g., a ransomware affiliate seen in your sector in the last 12 months).
- A kill-chain segment you have little evidence for (credential access → lateral movement).
- Validation of a new control or telemetry source (new EDR, Sysmon config, identity protection).

Derive procedures from CTI (see `intel-to-detection` and `campaign-correlation`): ATT&CK techniques **and** the concrete procedure the actor used, not just the technique ID.

## 2. Procedure list

| # | Technique | Procedure (actor-realistic) | Tool | Target | Expected telemetry | Expected detection |
|---|---|---|---|---|---|---|
| 1 | T1566.001 | Container file (ISO/ZIP) attachment with a shortcut, benign payload | Manual, test mailbox | Test mailbox | Mail flow, file creation, LNK exec | Mail gateway + EDR LNK child process |
| 2 | T1059.001 | Encoded PowerShell command fetching a benign test file | Atomic T1059.001 | WS-PT1 | 4104 script block, process creation | Encoded PS rule |
| 3 | T1003.001 | LSASS memory access with a built-in Windows component (as in the CTI report) | Atomic T1003.001 | WS-PT1 | Sysmon 10 / EDR LSASS access | LSASS access rule |
| 4 | T1021.002 | Remote service execution over SMB with a test admin account | Atomic T1021.002 | SRV-PT2 | 4624 type 3, service install 7045 | Lateral movement rule |
| 5 | T1547.001 | Run key persistence | Atomic T1547.001 | WS-PT1 | Registry set | Run key rule |

Keep 15-30 procedures for a day. Order them along the kill chain so later steps reuse earlier access.

## 3. Roles and ground rules

- **Exercise lead** (owns the schedule, safety calls), **operators** (execute), **detection engineers and SOC analysts** (search, tune), **scribe** (evidence log), **asset owners** on call.
- Signed rules of engagement and deconfliction (see `security-test-planning`, `attack-simulation-safety`).
- Dedicated test hosts and accounts tagged in the SIEM (`purple-team` tag) so any alert from them is routed to the exercise channel, not to on-call.

## 4. The loop per procedure

1. Operator announces and executes; scribe logs UTC time, host, command line.
2. Defenders check **telemetry first**: does the raw event exist? Record yes/no and the event IDs.
3. Then **detection**: did an alert fire, which rule, how fast, with what severity?
4. If missed: decide now whether it is a telemetry gap, rule gap or tuning gap. If a rule fix is quick, write it, deploy to test, re-run the procedure.
5. Record outcome: `blocked`, `detected`, `logged-only`, `not-logged`.

## 5. Evidence

Per procedure keep: exact command, timestamp, host, screenshots/exports of raw events, alert IDs, the rule version before and after tuning. After the exercise, score all procedures with `detection-validation` against the exported alerts so the report is not based on memory.

## 6. Outputs

```markdown
# Purple-team exercise: <objective>   Dates: <dates>   Lead: <role>
Procedures: 24   Blocked: 3   Detected: 12   Logged-only: 6   Not logged: 3
New/updated rules deployed during exercise: 5 (re-tested: 5 pass)
## Backlog
| ID | Gap type | Technique | Fix | Owner | Due | Re-test date |
## ATT&CK layer: tested coverage as of <date> (attached)
```

Schedule a re-test of every backlog item; an unverified fix is still a gap.

## Common mistakes

- Running default Atomic tests only: they detect the tool, not the actor's procedure.
- Testing on hosts without production-like agents and policies.
- No telemetry check: a "missed" detection that was never logged gets a rule written against data that does not exist.
- Leaving test persistence or accounts behind (cleanup checklist in `attack-simulation-safety`).

## Related skills

`detection-validation`, `security-test-planning`, `attack-simulation-safety`, `detection-testing`, `attack-coverage-mapping`, `hunt-to-detection`

## References

- MITRE ATT&CK: https://attack.mitre.org/
- SCYTHE Purple Team Exercise Framework (PTEF): https://github.com/scythe-io/purple-team-exercise-framework
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- MITRE Center for Threat-Informed Defense, Adversary Emulation Library: https://github.com/center-for-threat-informed-defense/adversary_emulation_library
