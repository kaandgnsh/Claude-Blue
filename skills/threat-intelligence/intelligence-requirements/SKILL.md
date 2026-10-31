---
name: intelligence-requirements
description: Define and maintain priority intelligence requirements (PIRs) and a threat profile — relevant actors, motivations, targeted technologies, crown jewels — and drive collection, production and feedback in the intelligence cycle. Use when starting or refocusing a CTI program, prioritizing feeds/vendors, or justifying what intel the SOC should act on.
license: MIT
metadata:
  category: threat-intelligence
  version: "2.0.0"
  verification: documented
---

# Intelligence Requirements

## Intelligence cycle

Direction (requirements) → Collection → Processing → Analysis → Dissemination → Feedback. Most failing CTI programs skip direction and drown in feeds.

## Building PIRs

1. Interview stakeholders: CISO/risk (strategic), SOC/IR/vuln mgmt (operational/tactical), fraud, product security.
2. Identify crown jewels and business context: sector, geographies, key suppliers, technology stack (VPNs, firewalls, IdP, SaaS, CI/CD).
3. Build a **threat profile**: actor types (ransomware affiliates, initial access brokers, state actors, insiders, hacktivists), motivations, and their known TTPs against peers.
4. Write PIRs as questions with consumers and decisions:
   - "Which ransomware groups are actively exploiting edge devices we operate (Fortinet, Citrix, Ivanti, Palo Alto) and how?" → vuln mgmt / SOC / patch prioritization.
   - "Are our credentials, sessions or data being sold or leaked?" → identity team / IR.
   - "Which techniques are being used against our sector's SaaS/IdP tenants?" → detection engineering.
5. Break into specific intelligence requirements (SIRs) and indicators of collection; map collection sources to each.
6. Review quarterly; retire PIRs that drive no decisions.

## PIR register

`PIR ID | Question | Consumer | Decision supported | Collection sources | Products/cadence | Last reviewed | Value feedback`

## Measuring value

Track actions taken from intel (detections built, patches prioritized, blocks, hunts) per PIR — not number of IOCs ingested.

## Related skills

`intel-report-writing`, `intel-to-detection`, `attack-coverage-mapping`, `risk-register`

## References

- FIRST CTI SIG curriculum: https://www.first.org/global/sigs/cti/curriculum/
- SANS CTI requirements (FOR578 materials/blog): https://www.sans.org/blog/
- CREST "What is Cyber Threat Intelligence": https://www.crest-approved.org/
