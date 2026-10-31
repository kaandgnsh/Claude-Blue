---
name: zero-trust-assessment
description: Assess zero trust maturity across identity, devices, networks, applications/workloads and data using the CISA Zero Trust Maturity Model 2.0 and NIST SP 800-207 — evidence-based scoring, gap prioritization and a roadmap. Use when planning a zero trust program, reporting maturity to leadership, or evaluating whether a "ZTNA" deployment actually reduces implicit trust.
license: MIT
metadata:
  category: security-architecture
  version: "2.0.0"
  verification: documented
---

# Zero Trust Assessment

## Pillars and evidence (CISA ZTMM 2.0: Traditional → Initial → Advanced → Optimal)

| Pillar | Evidence to collect |
|---|---|
| Identity | Phishing-resistant MFA coverage, centralized IdP, risk-based access, JIT privileged access, identity lifecycle automation |
| Devices | Inventory completeness, compliance checks used in access decisions, EDR coverage, managed vs. unmanaged access paths |
| Networks | Segmentation/microsegmentation, encrypted internal traffic, east-west controls, removal of flat VPN access |
| Applications & workloads | Per-app access (ZTNA/identity-aware proxy) instead of network-level access, workload identity, secure SDLC, continuous authorization |
| Data | Inventory/classification, access control by data sensitivity, DLP, encryption, monitoring of data access |
| Cross-cutting | Visibility & analytics, automation & orchestration, governance |

## Method

1. For each pillar function, score current state **with evidence** (config exports, coverage metrics) — not interviews alone.
2. Identify implicit trust remaining: "on the network = trusted", VPN to full subnets, service accounts with broad network reach, legacy apps without modern auth.
3. Prioritize by attack paths seen in incidents (credential theft → lateral movement → data): usually identity (phishing-resistant MFA, admin JIT) and device trust first, then app-level access replacing VPN, then segmentation.
4. Roadmap with measurable targets (e.g., "90% of internal web apps behind identity-aware proxy by Q3").

## ZTNA reality check

A ZTNA product that grants users access to whole subnets is VPN with extra steps. Verify per-app policies, device posture enforcement, and continuous evaluation.

## Output

`Pillar | Function | Current stage | Evidence | Target stage | Gap | Initiative | Owner | Date`

## Related skills

`architecture-review`, `network-segmentation-review`, `authentication-policy-review`, `conditional-access-review`

## References

- CISA Zero Trust Maturity Model v2.0: https://www.cisa.gov/zero-trust-maturity-model
- NIST SP 800-207 Zero Trust Architecture: https://csrc.nist.gov/pubs/sp/800/207/final
- NIST SP 1800-35 Implementing a Zero Trust Architecture: https://www.nccoe.nist.gov/projects/implementing-zero-trust-architecture
