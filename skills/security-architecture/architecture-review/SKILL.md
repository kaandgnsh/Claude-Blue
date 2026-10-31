---
name: architecture-review
description: Perform a security architecture review of a system or platform — context and data flows, identity and access design, network and trust boundaries, data protection, secrets, logging, resilience, third-party dependencies — against reference architectures and produce prioritized design findings. Use for design reviews before build or major change, platform assessments, or due diligence of a new technology.
license: MIT
metadata:
  category: security-architecture
  version: "2.0.0"
  verification: documented
---

# Security Architecture Review

## Inputs

Architecture diagrams (context, container, deployment), data classification, user and admin journeys, integration list, hosting model, compliance requirements, non-functional requirements (availability, RTO/RPO).

## Review domains and key questions

| Domain | Questions |
|---|---|
| Identity | How do users, admins, services authenticate? SSO + MFA? Service-to-service identity (mTLS, workload identity)? Admin path separate and JIT? |
| Authorization | Where is it enforced? Tenant isolation model? Least privilege for components? |
| Trust boundaries | Which components accept input from less-trusted zones? (`trust-boundary-analysis`) |
| Network | Exposure minimal? Private connectivity to data stores? Egress controlled? |
| Data | Classification, encryption at rest/in transit, key ownership, retention, backups, data residency |
| Secrets | Stored in a manager; rotation; no static long-lived keys |
| Software supply chain | Build provenance, dependency policy, image signing |
| Logging & detection | Security events logged, centralized, retained, alertable (`logging-architecture`) |
| Resilience | Failure modes, DDoS, ransomware recovery (immutable backups), dependency on single regions/providers |
| Third parties | SaaS/API dependencies, their access and data |
| Operations | Patching, configuration management, admin tooling security |

## Method

1. Walk the main flows with the architects; mark each boundary crossing.
2. Compare with reference patterns (cloud well-architected security pillars, zero trust).
3. Threat model the riskiest flows (`threat-modeling`).
4. Rate findings by impact × likelihood and *cost to fix later* (design flaws are expensive post-launch).
5. Agree mitigations/owners; record accepted risks.

## Output

`Finding | Domain | Description | Risk | Recommendation | Effort | Owner | Decision`

## Related skills

`threat-modeling`, `trust-boundary-analysis`, `zero-trust-assessment`, `cryptographic-design-review`

## References

- AWS Well-Architected Security Pillar: https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html
- Microsoft Cloud Security Benchmark: https://learn.microsoft.com/en-us/security/benchmark/azure/overview
- NIST SP 800-160 Vol. 1 Rev. 1 Engineering Trustworthy Secure Systems: https://csrc.nist.gov/pubs/sp/800/160/v1/r1/final
