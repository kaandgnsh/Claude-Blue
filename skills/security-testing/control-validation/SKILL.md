---
name: control-validation
description: Prove that preventive and detective controls work as configured (EDR blocking, ASR rules, application control, egress filtering, DNS filtering, MFA and conditional access, email attachment filtering, DLP) with safe, repeatable test cases and recorded evidence instead of console screenshots of policy settings. Use when assuring a control after deployment or change, preparing audit evidence of operating effectiveness, or investigating why an incident bypassed a control.
license: MIT
metadata:
  category: security-testing
  version: "2.2.0"
  verification: documented
---

# Control Validation

A policy that is "enabled" in a console is a claim. Validation is running a harmless input that the control must stop or log, on a representative target, and keeping the evidence. Test what the control is for, not what the setting is called.

## 1. Build the control test matrix

| Control | Claim | Safe test | Expected result | Evidence |
|---|---|---|---|---|
| EDR anti-malware | Blocks known malware on write | Write the EICAR test file | Quarantined, alert raised | EDR alert ID, quarantine record |
| ASR "Block Office child processes" | Office cannot spawn processes | Microsoft ASR test document | Blocked, event 1121 | Event log, Defender alert |
| Application control (WDAC/AppLocker) | Unsigned binaries in user paths cannot run | Copy a benign unsigned test binary to `%TEMP%` and run | Blocked, CodeIntegrity event | Event 3077 / 8004 |
| Egress filtering | Only proxy may reach the internet on 80/443 | `curl -m 5 https://example.com` directly from a server subnet | Connection fails; firewall deny log | Firewall log line |
| DNS filtering | Known-bad categories blocked | Resolve vendor-provided test domain | Sinkhole answer, log entry | Resolver log |
| MFA / conditional access | Legacy auth blocked; MFA required off-network | Sign-in with a test account from outside, legacy protocol attempt | MFA prompt; legacy auth denied | Sign-in log entries with CA result |
| Mail attachment filtering | Executable attachments blocked | Send EICAR in a zip and a renamed `.exe` from an external test mailbox | Rejected or quarantined | Message trace |
| DLP | Card numbers cannot leave via email | Send test card numbers (published test PANs) externally | Blocked or policy tip | DLP incident ID |

Use vendor-provided test artifacts where they exist; they are designed to trigger the control without real risk.

## 2. Pick representative targets

- At least one target per policy scope (each device group, OS version, OU, conditional access policy).
- Include the exceptions: servers with relaxed policies, VDI images, kiosk devices, developer machines with local admin.
- Run as a normal user and, where relevant, as a local admin (many controls behave differently).

## 3. Execute and capture

For each test record: control, target, account, UTC time, exact action, result (`prevented`, `detected-only`, `allowed-silent`), evidence reference. `allowed-silent` is the critical finding: the control neither stopped nor saw the action.

```kusto
// Defender for Endpoint: confirm ASR blocks during the test window
DeviceEvents
| where Timestamp between (datetime(2026-10-30T09:00:00Z) .. datetime(2026-10-30T12:00:00Z))
| where ActionType startswith "Asr" and DeviceName in~ ("ws-ct01", "ws-ct02")
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessFileName
```

```kusto
// Entra ID: conditional access result for the test account
SigninLogs
| where TimeGenerated > ago(1d) and UserPrincipalName == "ct-test01@contoso.example"
| project TimeGenerated, AppDisplayName, ClientAppUsed, ResultType, ConditionalAccessStatus, AuthenticationRequirement
```

## 4. Schedule

- After every policy change: the tests for the changed control.
- Monthly: high-value controls (EDR prevention, egress, MFA/CA). Automate the safe ones (EICAR drop, egress probe) with a scheduled job that alerts when the result changes.
- Annually or for audit: the full matrix with evidence pack.

## 5. Report

```markdown
# Control validation: <scope>   Period: <dates>
| Control | Targets | Prevented | Detected-only | Allowed-silent | Notes |
Allowed-silent findings: <list with owner and due date>
Evidence pack: <location>; test accounts disabled after test: yes
```

Map results to the control framework used for audits (e.g., NIST SP 800-53 SI-3 malicious code protection, SC-7 boundary protection, IA-2 MFA) when the evidence is for compliance (see `control-testing-sampling`).

## Related skills

`attack-simulation-safety`, `security-test-planning`, `bas-results-review`, `control-testing-sampling`, `edr-coverage-health`, `exposure-validation`

## References

- EICAR anti-malware test file: https://www.eicar.org/download-anti-malware-testfile/
- Microsoft Defender ASR rules, test in audit mode: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-test
- Microsoft Entra Conditional Access what-if and sign-in logs: https://learn.microsoft.com/en-us/entra/identity/conditional-access/what-if-tool
- NIST SP 800-53A Rev. 5 (assessing controls): https://csrc.nist.gov/pubs/sp/800/53/a/r5/final
