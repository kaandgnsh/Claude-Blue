---
name: evidence-intake
description: Receive, document, hash and preserve digital evidence (disk images, memory dumps, logs, cloud exports, mobile extractions) with chain of custody suitable for legal proceedings. Use when evidence is collected or handed over, when a legal hold is issued, or before any forensic analysis begins.
license: MIT
metadata:
  category: dfir
  version: "2.0.0"
  verification: documented
---

# Evidence Intake and Chain of Custody

Analysis on unverified evidence is worthless in court and unreliable in the SOC. Hash at acquisition, hash at receipt, work on copies.

## Intake workflow

1. **Record provenance**: who collected, when (UTC), from which system (hostname, serial, asset tag, cloud resource ARN/ID), with which tool and version, by what method (live/dead, logical/physical).
2. **Verify integrity**: compute and compare hashes against the collector's values.
   - Linux/macOS: `sha256sum evidence.E01` / `shasum -a 256 evidence.E01`
   - Windows: `Get-FileHash -Algorithm SHA256 .\evidence.E01`
   - E01 internal verification: `ewfverify evidence.E01`
3. **Assign an evidence ID** and label (case-ID-item-number), record storage location.
4. **Store the original read-only** (WORM bucket, write-protected share, or sealed media). Make a working copy and verify its hash.
5. **Log every access/transfer** in the custody form.
6. **Apply retention/legal hold** tags per counsel.

## Chain of custody record

```
Evidence ID: <CASE-001-003>   Description: <disk image of LAPTOP-123, 512GB NVMe>
Collected by: <name> on <UTC> using <tool vX.Y> method <physical, write-blocked>
Source identifiers: <hostname, serial, asset tag / cloud resource ID>
Hashes: SHA256 <> (acquisition)  SHA256 <> (receipt)  match: yes/no
Storage: <location>  Access: <restricted group>
Transfers:
  <UTC> | from <> | to <> | purpose | signature
```

## Cloud & log evidence notes

- Export logs with the query, time range, and record count; hash the export file.
- Snapshots (EBS, Azure managed disk, GCE PD) → record snapshot ID, source volume, account/subscription, region; copy to a forensic account with restricted access.
- Preserve provider-side logs early — CloudTrail management events are viewable for 90 days via Event history only; M365 audit retention depends on licensing.

## Pitfalls

- MD5-only hashing (acceptable as secondary, use SHA-256 as primary).
- Analysing originals; mounting images read-write (`mount -o ro,noexec,loop` or use forensic tools).
- Missing timezone on collection times.
- Screenshots without URL, time and account context.

## Related skills

`forensic-imaging`, `memory-forensics`, `forensic-report`, `case-documentation`

## References

- NIST SP 800-86: https://csrc.nist.gov/pubs/sp/800/86/final
- RFC 3227, Guidelines for Evidence Collection and Archiving: https://www.rfc-editor.org/rfc/rfc3227
- ISO/IEC 27037 (identification, collection, acquisition, preservation of digital evidence)
