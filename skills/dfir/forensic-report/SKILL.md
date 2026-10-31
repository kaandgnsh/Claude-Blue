---
name: forensic-report
description: Write a forensic examination report that states questions examined, evidence and its integrity, methods and tool versions, findings with artefact citations, limitations and conclusions, suitable for legal review. Use when concluding a forensic examination or preparing findings for counsel, HR, insurers or court.
license: MIT
metadata:
  category: dfir
  version: "2.0.0"
  verification: documented
---

# Forensic Report

A forensic report must be **reproducible**: another examiner using your evidence and methods should reach the same findings.

## Structure

1. **Summary of findings** — answers to each examination question in plain language.
2. **Examination questions / scope** — as tasked (by whom, date).
3. **Evidence examined** — ID, description, source, acquisition method, SHA-256 at acquisition and at examination.
4. **Methodology** — tools with versions, settings, analysis environment; deviations from standard procedure.
5. **Findings** — per question: observation → artefact (path, record, offset) → timestamp (UTC, source tz) → interpretation → confidence.
6. **Limitations** — encryption, missing logs, anti-forensics, timestamp ambiguity, retention, alternative explanations considered.
7. **Conclusions** — only what findings support.
8. **Appendices** — timeline excerpt, hash lists, tool output references, glossary.

## Language

- "The artefact indicates…" vs. "The user did…": attribute actions to an *account* unless physical-presence evidence ties a person to it.
- Quantify: "Prefetch shows `rclone.exe` executed 4 times; last run 2025-03-04 02:13:55 UTC".
- State alternative explanations considered and why rejected.

## Finding template

```
Finding <n>: <statement>
Artefact: <path / record id / offset>   Tool: <name vX>   Evidence ID: <>
Time: <UTC> (source recorded <local tz>)
Interpretation: <>
Confidence: confirmed/likely/possible   Alternatives considered: <>
```

## Peer review checklist

- [ ] Every finding cites an artefact location and evidence ID.
- [ ] Hashes in the report match the evidence log.
- [ ] Tool versions are recorded; any tool errors or parsing failures are disclosed.
- [ ] Times state both UTC and the source timezone where they differ.
- [ ] Conclusions don't exceed findings (no intent attributed without evidence).
- [ ] Limitations section names concrete gaps (encrypted container X, logs rolled before date Y).
- [ ] A second examiner reproduced the key findings.

## Related skills

`evidence-intake`, `timeline-analysis`, `incident-report-writing`

## References

- NIST SP 800-86: https://csrc.nist.gov/pubs/sp/800/86/final
- SWGDE best practices documents: https://www.swgde.org/documents/published-complete-listing
