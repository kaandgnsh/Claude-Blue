---
name: alert-triage
description: Triage a SIEM, EDR, email or cloud security alert to a true-positive, benign-true-positive or false-positive verdict with evidence, severity and next action. Use when an analyst asks "is this alert real?", needs to work an alert from a queue, or must decide whether to escalate.
license: MIT
metadata:
  category: soc-operations
  version: "2.0.0"
  verification: documented
---

# Alert Triage

Turn one alert into a defensible verdict in minutes, not a guess. The goal is a decision (close, tune, escalate, contain), not an essay.

## Inputs

- Alert payload: rule name/ID, product, raw event(s), entity fields (host, user, IP, hash, URL, process, cloud principal), first/last seen, count.
- Rule logic or documentation (what the rule actually matches — read it, do not infer from the title).
- Access to the SIEM/EDR to pivot ±24h around the event.

## Workflow

1. **Read the rule, then the raw event.** Confirm which field values made it fire. Many "malicious PowerShell" alerts are a single substring match.
2. **Identify entities and their context** (asset criticality, owner, user role, is the host a server/DC/jump box, is the account privileged or a service account).
3. **Answer the five triage questions** with evidence:
   - *What executed / authenticated / connected?* (exact command line, parent, signer, hash, logon type)
   - *Is this normal for this entity?* (has this host/user done this in the last 30 days?)
   - *Is there a precursor?* (phish delivery, new logon, download, exploit attempt in prior 1–24h)
   - *Is there follow-on activity?* (child processes, network connections, new persistence, lateral logons)
   - *Is there a benign explanation with proof?* (change ticket, IT tooling, scanner IP, pentest scope)
4. **Pivot efficiently** (examples; adapt to your schema):
   - Splunk: `index=edr host="HOST" earliest=-24h | stats count values(CommandLine) by ParentImage, Image | sort -count`
   - Sentinel: `DeviceProcessEvents | where DeviceName =~ "HOST" and Timestamp > ago(24h) | summarize count(), make_set(ProcessCommandLine, 20) by InitiatingProcessFileName, FileName`
   - Prevalence of a hash: `DeviceFileEvents | where SHA256 == "<hash>" | summarize dcount(DeviceId), min(Timestamp)`
5. **Enrich indicators** (hash/IP/domain reputation, first-seen, WHOIS age, passive DNS). Reputation is supporting evidence only; a clean VT score does not clear a novel binary.
6. **Assign verdict and severity** using the matrix below and record it.
7. **Act**: close with reason code, open tuning request, or escalate with a handoff summary. If containment is warranted, follow `host-isolation` / `containment-plan` with approval.

## Verdict definitions

| Verdict | Meaning | Required evidence |
|---|---|---|
| True positive (TP) | Malicious or unauthorized activity | Behavior + context showing intent/unauthorized |
| Benign true positive (BTP) | Rule worked, activity authorized | Ticket, owner confirmation, or known tooling |
| False positive (FP) | Rule logic matched the wrong thing | Explanation of the mismatch → tuning request |
| Undetermined | Insufficient telemetry | List the missing data; escalate, don't close |

Severity = impact of the entity × confidence × stage. A confirmed TP on a domain controller or with credential access is high/critical regardless of rule severity.

## Common traps

- Closing because "the user said it was them" without verifying the source (MFA prompt, device ID, IP).
- Treating absence of EDR telemetry as absence of activity (check sensor health and last check-in).
- Trusting the alert's timestamp timezone; normalize to UTC.
- Auto-closing duplicates without checking whether the entity set changed.

## Output template

```
Alert: <rule> (<id>)  Product: <src>  Time (UTC): <t>
Entities: host=<> user=<> ip=<> hash=<>
Verdict: TP | BTP | FP | Undetermined   Confidence: high/med/low   Severity: <>
Evidence:
 - <query/link> → <finding>
Benign explanation checked: <ticket/owner/none>
Action: close (reason) | tune (request id) | escalate to <tier/IR> | contain (approval: <>)
Open questions: <>
```

## Safety

Read-only pivots only during triage. Do not run the suspected file, detonate on a production host, or contact a suspected attacker-controlled endpoint. Containment requires the approval path in `host-isolation`.

## Related skills

`alert-tuning`, `escalation-decision`, `edr-alert-investigation`, `process-tree-analysis`, `ioc-assessment`, `case-documentation`

## References

- NIST SP 800-61r3, Incident Response Recommendations (2025): https://csrc.nist.gov/pubs/sp/800/61/r3/final
- MITRE ATT&CK: https://attack.mitre.org/
