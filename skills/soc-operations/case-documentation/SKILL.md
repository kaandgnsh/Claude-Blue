---
name: case-documentation
description: Write or review a security case record so another analyst, auditor or court can reconstruct what was known, when, and why each decision was made. Use when closing a case, preparing a case for escalation or legal hold, or auditing case quality.
license: MIT
metadata:
  category: soc-operations
  version: "2.0.0"
  verification: documented
---

# Case Documentation

A case file is evidence of your reasoning. If it is not written down with a source and time, it did not happen.

## Minimum case record

| Field | Content |
|---|---|
| Summary | 2–3 sentences: what happened, impact, current status |
| Timeline | UTC timestamps, event, source system, analyst action |
| Entities | Hosts, accounts, IPs, hashes, URLs — with how each was linked to the case |
| Evidence | Query text or saved-search link, export hash, screenshot path, collection ID |
| Analysis | Facts vs. assessments vs. hypotheses, clearly labeled |
| Decisions | What was decided, by whom, at what time, based on which evidence |
| Actions | Containment/remediation steps, approver, ticket, verification result |
| Disposition | Verdict, reason code, root cause, lessons/tuning requests |

## Workflow

1. **Separate observation from inference.** Write "4624 logon type 10 from 203.0.113.7 at 02:14Z (source: DC01 Security log)" — not "attacker RDP'd in".
2. **Record every query that drove a decision**, verbatim, with the time range and the result count. A saved-search link alone can rot.
3. **Hash exported evidence** (`sha256sum export.csv`) and note where it is stored.
4. **Use confidence language consistently**: *confirmed* (direct evidence), *likely* (strong indirect), *possible* (consistent but unverified), *unknown*.
5. **Record negative findings with scope**: "No 4688 events for mimikatz.exe on HR-* hosts 01–07 Oct; 4688 command-line auditing enabled on 38/41 hosts" — never just "nothing found".
6. **Close with a reason code** from a fixed list (TP-contained, BTP-authorized, FP-logic, FP-data, Duplicate, Insufficient-data) so metrics work.

## Review checklist (case QA)

- [ ] Another analyst could reproduce each key finding from the record.
- [ ] Timeline is in UTC and ordered; gaps are explained.
- [ ] Each entity has a provenance ("from alert", "from pivot query X").
- [ ] Decisions name the decision-maker and timestamp.
- [ ] Sensitive data is minimized (no full credential values, no unnecessary PII).
- [ ] Follow-ups (tuning, detection gap, vuln) have tickets.

## Output template

```
Case <id> — <title>
Status: open/closed  Severity: <>  Verdict: <>  Reason code: <>
Summary: <>
Timeline (UTC):
  <t> | <event> | <source> | <analyst/action>
Evidence: <item> | <location> | sha256=<>
Decisions: <t> <who> decided <what> because <evidence>
Follow-ups: <ticket ids>
```

## Safety

Case records may become discoverable in litigation. Write factually, avoid speculation about individuals' intent, and follow legal-hold instructions from counsel.

## Related skills

`alert-triage`, `forensic-report`, `incident-report-writing`, `evidence-intake`

## References

- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-86 (integrating forensic techniques): https://csrc.nist.gov/pubs/sp/800/86/final
