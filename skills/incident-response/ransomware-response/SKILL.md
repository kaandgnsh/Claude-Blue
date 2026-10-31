---
name: ransomware-response
description: Respond to a ransomware or extortion incident — stop encryption spread, preserve evidence, identify the variant and access vector, assess data theft, protect backups and drive recovery decisions. Use when encryption, ransom notes, mass file renames, shadow-copy deletion or a data-leak-site extortion claim is observed.
license: MIT
metadata:
  category: incident-response
  version: "2.0.0"
  verification: documented
---

# Ransomware Response

Modern ransomware is usually *double extortion*: data theft precedes encryption, often by days. Restoring files does not end the incident.

## Immediate actions (first hour)

1. **Isolate affected hosts via EDR** and, if spreading, segment at the network (block SMB/RDP east-west, disable VPN for affected users). Prefer isolation over power-off to keep memory.
2. **Protect backups**: confirm backup consoles and repositories are not reachable from compromised credentials; disable compromised backup admin accounts; verify immutability/air-gap copies.
3. **Disable or reset compromised privileged accounts**; identify accounts used for deployment (GPO, PsExec, SCCM, RMM tools).
4. **Preserve**: memory from 1–2 representative hosts, a ransom note, an encrypted file sample, the encryptor binary if found, relevant logs (DC, VPN, EDR) before they roll.
5. **Engage**: IC, legal/counsel (privilege), cyber insurer (notification clause), IR retainer, executive crisis team.

## Investigation

| Question | Sources |
|---|---|
| Variant? | Ransom note, extension, ID Ransomware, No More Ransom; vendor intel |
| Initial access? | VPN/RDP logs, exploited edge device (check CISA KEV), phishing, valid accounts |
| Deployment method? | GPO changes (5136), service installs (7045), PsExec, scheduled tasks, RMM tools |
| Data exfiltration? | Large outbound transfers, rclone/MEGAsync/WinSCP execution, cloud storage uploads, proxy logs |
| Dwell time? | Earliest attacker artifact vs. encryption time |

Encryption precursors to hunt/alert on: `vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit /set {default} recoveryenabled no`, `wbadmin delete catalog`, mass service stop of SQL/backup/AV, `Set-MpPreference -DisableRealtimeMonitoring`.

## Decision points for leadership

- Restore vs. rebuild scope; restore order (`critical-service-mapping`).
- Extortion response: payment decisions are legal/board decisions; check sanctions screening (e.g., OFAC advisory) and law-enforcement engagement. Analysts provide facts, not recommendations to pay.
- Regulatory and customer notification if data was stolen (`privacy-incident-assessment`).

## Output template

```
Ransomware incident <id> — <UTC>
Variant: <> (confidence)  Encryption start: <t>  Affected: <n hosts/services>
Initial access: <>  Dwell time: <>
Exfiltration: confirmed/likely/not observed (evidence)
Backups: status/integrity/immutability
Containment status: <>
Decisions needed: <>
```

## Safety

Do not run the encryptor, do not contact the threat actor (negotiation is done by designated specialists under counsel), and do not wipe encrypted systems before evidence and decryption options are evaluated.

## Related skills

`ransomware-recovery`, `containment-plan`, `backup-assurance`, `incident-scoping`, `privacy-incident-assessment`

## References

- CISA #StopRansomware Guide: https://www.cisa.gov/stopransomware/ransomware-guide
- No More Ransom: https://www.nomoreransom.org/
- OFAC updated advisory on ransomware payments (2021): https://ofac.treasury.gov/recent-actions/20210921
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
